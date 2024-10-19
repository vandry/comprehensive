//! A collection of assembled runnable [`Resource`] objects
//!
//! A [`Resource`] is an item of work which may depend on other resources
//! and gets bundled with other resources into an [`Assembly`] where all
//! the resources form a directed acyclic graph with the edges representing
//! their dependency relationships.
//!
//! Only one instance of each type that implements the [`Resource`] trait
//! exists in an [`Assembly`]: resources are meant to be shared by all
//! consumers.
//!
//! Examples of typical resources types are:
//! * server infrastructure, such as an HTTP server, or a piece of
//!   reloadable application configration)
//! * services exported by the server, like a gRPC service implementation
//!   or an HTTP endpoint handler (these types are expected to install
//!   themselves into the relevant infrastructure resource by depending
//!   upon it and hooking into it at construction time)
//! * stubs for services consumed by other resources, like databases or
//!   remote RPC services
//! * background tasks (may be relatively independent of other resources
//!   in the graph and be inserted in the top-level dependencies in order
//!   to get into the assembly).
//!
//! The entry point to be called from the application's main function is
//! [`Assembly::new`].

use async_trait::async_trait;
use clap::{ArgMatches, Args, Command, FromArgMatches};
use downcast_rs::{impl_downcast, DowncastSync};
use futures::stream::FuturesUnordered;
use futures::{poll, stream_select, FutureExt, Stream, StreamExt};
use std::any::TypeId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::sync::{futures::Notified, Notify};

/// Passed to [`Resource::run_with_termination_signal`] to offer resources
/// a chance to react to a termination request signal. Interested resources
/// should call [`ShutdownNotify::subscribe`].
pub struct ShutdownNotify<'a>(&'a Notify);

impl<'a> ShutdownNotify<'a> {
    /// Returns a new [`Future`] which will resolve when termination
    /// is requested.
    pub fn subscribe(&'a self) -> Notified<'a> {
        self.0.notified()
    }

    /// Create a new notifier. Visible for testing.
    pub fn new(n: &'a Notify) -> Self {
        Self(n)
    }
}

#[async_trait]
trait ResourceObject: DowncastSync {
    async fn run<'a>(
        &self,
        selfindex: usize,
        subscribe_to_termination: &'a ShutdownNotify,
    ) -> (usize, Result<(), Box<dyn Error>>);
}
impl_downcast!(sync ResourceObject);

#[async_trait]
impl<T: Resource + Send> ResourceObject for T {
    async fn run<'a>(
        &self,
        selfindex: usize,
        subscribe_to_termination: &'a ShutdownNotify,
    ) -> (usize, Result<(), Box<dyn Error>>) {
        (
            selfindex,
            Resource::run_with_termination_signal(self, subscribe_to_termination).await,
        )
    }
}

/// The main unit of work in an [`Assembly`] and the trait common to each
/// of the nodes in its DAG.
#[allow(private_bounds)]
pub trait Resource: ResourceObject + Sized {
    /// Command line arguments that this [`Resource`] would like to receive.
    /// For example a resource that implements an HTTP server might use this
    /// to configure which address to listen on.
    ///
    /// This is expected to be a struct defined like so:
    ///
    /// ```
    /// #[derive(clap::Args, Debug)]
    /// #[group(skip)]
    /// struct Args {
    ///     #[arg(long)]
    ///     port: Option<u16>,
    /// }
    /// ```
    ///
    /// These args will be collected along with the args from all other
    /// resources into a [`clap::Parser`] and the individual Args instances
    /// will be handed to each resource at constrction time.
    type Args: clap::Args;

    /// Other resources that this [`Resource`] depends on. The resources
    /// in this collection will be constructed before this resource, then
    /// this structure will be filled in with [`Arc`] references to those
    /// constructed instances and passed to the constructor of the current
    /// resource.
    ///
    /// This type should satisfy the [`ResourceDependencies`] trait by
    /// deriving it.
    type Dependencies: ResourceDependencies;

    /// The name of this resource. Used in logs and resource graph
    /// diagnostics.
    const NAME: &str;

    /// Construct a resource of this type. Called while the graph of all
    /// resources is built in [`Assembly::new`].
    fn new(deps: Self::Dependencies, args: Self::Args) -> Result<Self, Box<dyn Error>>;

    /// Execute a background task belonging to this resource. Awaited
    /// together with the tasks for all other resourcees in [`Assembly::run`].
    ///
    /// The default implementation exits immediately.
    fn run(&self) -> impl Future<Output = Result<(), Box<dyn Error>>> + Send {
        async { Ok(()) }
    }

    /// Execute a background task belonging to this resource. Awaited
    /// together with the tasks for all other resourcees in [`Assembly::run`].
    ///
    /// The default implementation delegates to [`Resource::run`] except that
    /// it exits (successfully) as soon as a termination signal is received.
    fn run_with_termination_signal<'a>(
        &'a self,
        subscribe_to_termination: &'a ShutdownNotify<'a>,
    ) -> impl Future<Output = Result<(), Box<dyn Error>>> + Send + 'a {
        let term_signal = subscribe_to_termination.subscribe();
        async move {
            let runner = pin!(Resource::run(self));
            let term = pin!(term_signal.map(|_| Ok(())));
            futures::future::select(runner, term).await.factor_first().0
        }
    }
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct RegisterContext<'a> {
    registry: &'a mut HashMap<TypeId, bool>,
    command: Option<Command>,
    write_graph: Option<&'a mut dyn std::io::Write>,
    parent: Option<TypeId>,
}

struct ResourceEntry {
    name: &'static str,
    resource: Arc<dyn ResourceObject>,
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct ProduceContext<'a> {
    registry: &'a mut HashMap<TypeId, ResourceEntry>,
    arg_matches: &'a mut ArgMatches,
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct Registrar<T> {
    _never_constructed: T,
}

impl<T: Resource> Registrar<T> {
    pub fn register(cx: &mut RegisterContext<'_>) {
        let me = TypeId::of::<T>();
        if let Some(ref mut w) = cx.write_graph {
            writeln!(
                w,
                "  \"{}\" -> \"t-{:?}\"",
                match cx.parent {
                    Some(ref tid) => format!("t-{:?}", tid),
                    None => String::from("top"),
                },
                me
            )
            .unwrap();
        }
        match cx.registry.entry(me) {
            Entry::Vacant(e) => e.insert(false),
            Entry::Occupied(e) => match e.get() {
                false => {
                    panic!(
                        "Disallowed cyclic dependency in Comprehensive graph involving {}",
                        T::NAME
                    );
                }
                true => {
                    return;
                }
            },
        };
        let old_parent = if let Some(ref mut w) = cx.write_graph {
            writeln!(w, "  \"t-{:?}\" [label={:?}]", me, T::NAME).unwrap();
            cx.parent.replace(me)
        } else {
            None
        };
        T::Dependencies::register(cx);
        cx.parent = old_parent;
        cx.command = Some(T::Args::augment_args(cx.command.take().unwrap()));
        cx.registry.entry(me).and_modify(|v| *v = true);
    }

    pub fn produce(cx: &mut ProduceContext<'_>) -> Result<Arc<T>, Box<dyn Error>> {
        let me = TypeId::of::<T>();
        let v = match cx.registry.get(&me) {
            None => {
                let deps = T::Dependencies::produce(cx)?;
                let args = T::Args::from_arg_matches(cx.arg_matches)?;
                let v: Arc<dyn ResourceObject> = Arc::new(T::new(deps, args)?);
                cx.registry.insert(
                    me,
                    ResourceEntry {
                        name: T::NAME,
                        resource: Arc::clone(&v),
                    },
                );
                v
            }
            Some(v) => Arc::clone(&v.resource),
        };
        let Ok(v) = v.downcast_arc::<T>() else {
            panic!("bad downcast");
        };
        Ok(v)
    }
}

/// This trait expresses the collection of types of other resources that a
/// [`Resource`] depends on. It is also used to list the top-level resource
/// types at the roots of the [`Assembly`] graph.
///
/// This must be implemented on a struct containing zero or more fields of
/// type [`Arc<T>`] where T is a [`Resource`]. On that structure, the trait
/// should be derived.
///
/// ```
/// use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
/// use std::sync::Arc;
///
/// # struct OtherResource;
/// # impl comprehensive::Resource for OtherResource {
/// #     type Args = NoArgs;
/// #     type Dependencies = NoDependencies;
/// #     const NAME: &str = "other resource";
/// #
/// #     fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
/// #         Ok(Self)
/// #     }
/// # }
/// # type ImportantResource = OtherResource;
/// #
/// #[derive(ResourceDependencies)]
/// struct DependenciesOfSomeResource {
///     other_resource: Arc<OtherResource>,
///     i_need_this: Arc<ImportantResource>,
/// }
/// ```
///
/// **On the use of [`Arc`]**: During initialisation, a [`Resource`] might
/// reasonably desire mutable references to its dependencies, but this is
/// not available since the dependencies are supplied as [`Arc<T>`].
/// Resources can get around this by offering interior mutability APIs
/// (such as [`std::sync::Mutex`]) to their consumers. This was a design
/// tradeoff. An alternative design was considered where the dependencies
/// were supplied as `&'a mut T` (where `'a` is the lifetime of the
/// [`Assembly`]) but that arguably had worse issues since resources could
/// not retain those references outside of [`Resource::new`] (since the
/// reference needs to be available to another consumer). Solutions are
/// possible in case more longer-lived access is required, but these are
/// arguably not better than the [`Arc`] solution.
pub trait ResourceDependencies: Sized {
    /// Opaque method used in the implementation of the
    /// [`ResourceDependencies`] trait, which should be derived.
    fn register(cx: &mut RegisterContext);

    /// Opaque method used in the implementation of the
    /// [`ResourceDependencies`] trait, which should be derived.
    fn produce(cx: &mut ProduceContext) -> Result<Self, Box<dyn Error>>;
}

pub use comprehensive_macros::ResourceDependencies;

/// Main entry point for a Comprehensive server.
///
/// ```
/// # #[derive(comprehensive::ResourceDependencies)]
/// # struct TopDependencies;
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///    comprehensive::Assembly::<TopDependencies>::new()?.run().await
/// }
pub struct Assembly<T> {
    resources: Box<[ResourceEntry]>,
    /// The constructed instances of the top-level (root) dependencies.
    /// Access to this is freqently not required as these resources
    /// will work autonomously once included in the graph.
    pub top: T,
}

#[derive(clap::Args, Debug, Default)]
#[group(skip)]
struct GlobalArgs {
    #[arg(
        long,
        exclusive = true,
        help = "Instead of running, write the Comprehensive Resource graph in Graphviz format and exit"
    )]
    write_graph_and_exit: bool,
}

fn mark_complete(names: &mut [Option<&'static str>], i: usize) -> &'static str {
    let Some(e) = names.get_mut(i) else {
        log::error!("Out of range resource with index {} finished", i);
        return "unknown resource";
    };
    let Some(e) = e.take() else {
        log::error!(
            "An already finished resource with index {} finished again",
            i
        );
        return "unknown resource";
    };
    e
}

fn active_list(names: &[Option<&'static str>]) -> String {
    let mut v = names.iter().filter_map(|n| *n).collect::<Vec<_>>();
    v.sort();
    v.join(", ")
}

impl<T> Assembly<T>
where
    T: ResourceDependencies,
{
    /// Build a new [`Assembly`] from the given resources and all their
    /// transitive dependencies.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut registry = HashMap::new();
        let mut cx = RegisterContext {
            registry: &mut registry,
            command: Some(clap::Command::new("Assembly")),
            write_graph: None,
            parent: None,
        };
        T::register(&mut cx);
        let command = GlobalArgs::augment_args(cx.command.take().unwrap());

        let mut arg_matches = command.get_matches();
        let global_args = GlobalArgs::from_arg_matches(&arg_matches)?;

        if global_args.write_graph_and_exit {
            Self::write_graph(&mut std::io::stdout());
            std::process::exit(0);
        }

        let mut registry = HashMap::new();
        let mut cx = ProduceContext {
            registry: &mut registry,
            arg_matches: &mut arg_matches,
        };
        let top = T::produce(&mut cx)?;
        let resources = registry
            .into_values()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self { resources, top })
    }

    /// Run an [`Assembly`] by invoking and awaiting [`Resource::run`] on every
    /// resource in the graph.
    ///
    /// Runs until either any [`Resource`] terminates with an error, or all
    /// resources terminate successfully. (Returns immediately on an empty
    /// graph.)
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        self.run_with_termination_signal(tokio_stream::wrappers::SignalStream::new(
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        ))
        .await
    }

    /// Run an [`Assembly`] by invoking and awaiting [`Resource::run`] on every
    /// resource in the graph.
    ///
    /// Callers should usually use [`Assembly::run`] instead, which installs a
    /// `SIGTERM` handler and then calls this with it.
    pub async fn run_with_termination_signal(
        self,
        termination_signal: impl Stream<Item = ()> + Unpin,
    ) -> Result<(), Box<dyn Error>> {
        let mut names = self
            .resources
            .iter()
            .map(|e| Some(e.name))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut running_count = self.resources.len();
        let mut quitting = false;
        let shutdown_notify = Notify::new();
        let notify_interface = ShutdownNotify(&shutdown_notify);
        log::info!(
            "Comprehensive starting with {} resources: {}",
            self.resources.len(),
            active_list(&names)
        );
        let mut stream: FuturesUnordered<_> = self
            .resources
            .iter()
            .enumerate()
            .map(|(i, entry)| entry.resource.run(i, &notify_interface))
            .collect();

        // Flush out all the initialisation work, including resources with empty
        // run methods.
        while let Poll::Ready(Some((i, result))) = poll!(stream.next()) {
            let name = mark_complete(&mut names, i);
            running_count -= 1;
            if let Err(e) = result {
                log::error!("{} failed: {}", name, e);
                return Err(e);
            }
        }

        // Blocking loop for the rest of time.
        log::info!(
            "After startup, {} resources are running: {}",
            stream.len(),
            active_list(&names)
        );
        let mut combined =
            stream_select!(stream.map(Some), termination_signal.map(|_| None));
        loop {
            if running_count == 0 {
                break;
            }
            let Some(r) = combined.next().await else {
                break;
            };
            match r {
                Some((i, result)) => {
                    let name = mark_complete(&mut names, i);
                    running_count -= 1;
                    match result {
                        Err(e) => {
                            log::error!("{} failed: {}", name, e);
                            return Err(e);
                        }
                        Ok(()) => {
                            log::info!("{} exited successfully", name);
                        }
                    }
                }
                None => {
                    if quitting {
                        log::warn!("SIGTERM received again; quitting immediately.");
                        break;
                    }
                    quitting = true;
                    log::warn!("SIGTERM received; shutting down");
                    shutdown_notify.notify_waiters();
                }
            }
        }
        Ok(())
    }

    /// Write the constructed graph in Graphviz dot format.
    ///
    /// Can be invoked by running an [`Assembly`] with the special flag
    /// `--write_graph_and_exit` on the command line.
    pub fn write_graph(w: &mut dyn std::io::Write) {
        writeln!(w, "digraph \"Assembly\" {{").unwrap();
        writeln!(w, "  top [shape=box]").unwrap();
        let mut registry = HashMap::new();
        let mut cx = RegisterContext {
            registry: &mut registry,
            command: Some(clap::Command::new("Assembly")),
            write_graph: Some(w),
            parent: None,
        };
        T::register(&mut cx);
        writeln!(w, "}}").unwrap();
    }
}

/// Convenience type that can be used as the `Dependencies` associated
/// type on any leaf [`Resource`].
#[derive(ResourceDependencies)]
pub struct NoDependencies;

/// Convenience type that can be used as the `Args` associated type on
/// any [`Resource`] that takes no command line arguments.
#[derive(clap::Args, Debug, Default)]
#[group(skip)]
pub struct NoArgs {}

#[cfg(test)]
mod tests {
    use super::*;

    use regex::Regex;
    use std::ops::Deref;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static CONSTRUCT_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct Leaf1 {}

    #[derive(Debug)]
    struct NoGood;

    impl std::fmt::Display for NoGood {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "no good")
        }
    }

    impl std::error::Error for NoGood {}

    impl Resource for Leaf1 {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "Leaf1";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            CONSTRUCT_COUNT.fetch_add(1, Ordering::Release);
            Ok(Self {})
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            Err(Box::new(NoGood))
        }
    }

    #[derive(Debug)]
    struct Leaf2 {}

    impl Resource for Leaf2 {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "Leaf2";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            CONSTRUCT_COUNT.fetch_add(1, Ordering::Release);
            Ok(Self {})
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }

    #[derive(ResourceDependencies)]
    struct MidDependencies(Arc<Leaf1>, Arc<Leaf2>);

    struct Mid {
        deps: MidDependencies,
    }

    impl Resource for Mid {
        type Args = NoArgs;
        type Dependencies = MidDependencies;
        const NAME: &str = "Mid";

        fn new(deps: MidDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            CONSTRUCT_COUNT.fetch_add(1, Ordering::Release);
            Ok(Self { deps })
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies {
        mid: Arc<Mid>,
        l2: Arc<Leaf2>,
    }

    // correct_number_of_resources is sensitive to being run at
    // the same time as anything else that also builds the graph.
    static SERIALISE_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn correct_number_of_resources() {
        let _guard = SERIALISE_TEST.lock().unwrap();
        let before = CONSTRUCT_COUNT.load(Ordering::Acquire);
        let _assembly = Assembly::<TopDependencies>::new().expect("assembly");
        let after = CONSTRUCT_COUNT.load(Ordering::Acquire);
        assert_eq!(after - before, 3);
    }

    #[test]
    fn correct_graph() {
        let mut output = Vec::new();
        Assembly::<TopDependencies>::write_graph(&mut output);
        let digraph = String::from_utf8(output).unwrap();
        let lines = digraph.split("\n").collect::<Vec<_>>();

        // The node ids are opaque. Let's map them.
        let mut names = HashMap::new();
        let re = Regex::new(r#".*"(t-[^"]+)".*label="([^"]+)".*"#).unwrap();
        for l in lines.iter() {
            if let Some(captures) = re.captures(l) {
                names.insert(
                    captures.get(1).unwrap().as_str().to_owned(),
                    captures.get(2).unwrap().as_str().to_owned(),
                );
            }
        }

        // Now get all edges.
        let mut edges = Vec::new();
        let re = Regex::new(r#".*"([^"]+)".*->.*"([^"]+)".*"#).unwrap();
        for l in lines.iter() {
            if let Some(captures) = re.captures(l) {
                let lhs = captures.get(1).unwrap().as_str();
                let lhs = names.get(lhs).map(|s| s.as_str()).unwrap_or(lhs);
                let rhs = captures.get(2).unwrap().as_str();
                let rhs = names.get(rhs).map(|s| s.as_str()).unwrap_or(rhs);
                edges.push((lhs, rhs));
            }
        }

        edges.sort();
        assert_eq!(
            edges,
            vec![
                ("Mid", "Leaf1"),
                ("Mid", "Leaf2"),
                ("top", "Leaf2"),
                ("top", "Mid")
            ]
        );
    }

    #[test]
    fn reachability() {
        let _guard = SERIALISE_TEST.lock().unwrap();
        let assembly = Assembly::<TopDependencies>::new().unwrap();
        let leaf2_1 = Arc::deref(&assembly.top.mid.deps.1) as *const Leaf2;
        let leaf2_2 = Arc::deref(&assembly.top.l2) as *const Leaf2;
        assert_eq!(leaf2_1, leaf2_2);
        // 1 path via the graph, 1 via the list of resources.
        assert_eq!(Arc::strong_count(&assembly.top.mid.deps.0), 2);
    }

    #[derive(ResourceDependencies)]
    struct CyclicDependencies(Arc<CyclicResource>);

    #[derive(Debug)]
    struct CyclicResource {}

    impl Resource for CyclicResource {
        type Args = NoArgs;
        type Dependencies = CyclicDependencies;
        const NAME: &str = "CyclicResource";

        fn new(d: CyclicDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            println!("{:?}", d.0); // silence "field is never read"
            Ok(Self {})
        }
    }

    #[test]
    #[should_panic(expected = "Disallowed cyclic dependency")]
    fn cyclic_dependency() {
        let _ = Assembly::<CyclicDependencies>::new().unwrap();
    }

    #[tokio::test]
    async fn run_assembly() {
        let res = {
            let _guard = SERIALISE_TEST.lock().unwrap();
            Assembly::<TopDependencies>::new()
        }
        .unwrap()
        .run_with_termination_signal(futures::stream::pending())
        .await;
        let Err(e) = res else {
            panic!("poll should have returned an error");
        };
        assert_eq!(e.to_string(), "no good");
    }

    struct RunUntilSignaled(Notify);

    impl Resource for RunUntilSignaled {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "RunUntilSignaled";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self(Notify::new()))
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            Ok(self.0.notified().await)
        }
    }

    #[derive(ResourceDependencies)]
    struct RunUntilSignaledTop(Arc<RunUntilSignaled>);

    #[tokio::test]
    async fn runs_until_resource_quits() {
        let assembly = Assembly::<RunUntilSignaledTop>::new().unwrap();
        let notify = &Arc::clone(&assembly.top.0).0;
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_pending());
        notify.notify_waiters();
        assert!(poll!(&mut r).is_ready());
    }

    #[tokio::test]
    async fn runs_until_overall_shutdown() {
        let assembly = Assembly::<RunUntilSignaledTop>::new().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r =
            pin!(assembly
                .run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx)));
        assert!(poll!(&mut r).is_pending());
        let _ = tx.send(()).await;
        assert!(poll!(&mut r).is_ready());
    }

    struct RunStubbornly;

    impl Resource for RunStubbornly {
        type Args = NoArgs;
        type Dependencies = NoDependencies;
        const NAME: &str = "RunStubbornly";

        fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }

        async fn run_with_termination_signal<'a>(
            &'a self,
            _subscribe_to_termination: &'a ShutdownNotify<'a>,
        ) -> Result<(), Box<dyn Error>> {
            Ok(futures::future::pending().await)
        }
    }

    #[derive(ResourceDependencies)]
    struct RunStubbornlyTop(Arc<RunStubbornly>);

    #[tokio::test]
    async fn needs_2_sigterms() {
        let assembly = Assembly::<RunStubbornlyTop>::new().unwrap();
        let _ = assembly.top.0;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r =
            pin!(assembly
                .run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx)));
        assert!(poll!(&mut r).is_pending());
        let _ = tx.send(()).await;
        // Does not quit after the first request.
        assert!(poll!(&mut r).is_pending());
        let _ = tx.send(()).await;
        // Does quit after the second.
        assert!(poll!(&mut r).is_ready());
    }
}
