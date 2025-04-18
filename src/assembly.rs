//! A collection of assembled runnable application components called Resources.
//!
//! A resource is an application component which may depend on other resources
//! and gets bundled with other resources into an [`Assembly`] where all
//! the resources form a directed acyclic graph with the edges representing
//! their dependency relationships.
//!
//! Only one instance of each type of Resource exists in an [`Assembly`]:
//! resources are meant to be shared by all consumers.
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

use clap::{ArgMatches, Args, FromArgMatches};
use fixedbitset::FixedBitSet;
use futures::stream::{FusedStream, FuturesUnordered};
use futures::{Stream, StreamExt, poll, ready};
use pin_project_lite::pin_project;
use std::any::{Any, TypeId};
use std::cell::OnceCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use topological_sort::TopologicalSort;

use crate::shutdown::{
    ShutdownSignal, ShutdownSignalForwarder, ShutdownSignalParticipantCreator, TaskRunningSentinel,
};

pub(crate) type ResourceFut = Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>>;

struct Node<T: sealed::ResourceBase<U>, const U: usize> {
    production: OnceCell<T::Production>,
}

impl<T: sealed::ResourceBase<U>, const U: usize> Default for Node<T, U> {
    fn default() -> Self {
        Self {
            production: OnceCell::new(),
        }
    }
}

trait NodeTrait: Any {
    fn name(&self) -> &'static str;
    fn augment_args(&self, _: clap::Command) -> clap::Command;
    fn make(
        &self,
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut ArgMatches,
        stoppers: ShutdownSignalParticipantCreator,
        keepalive: TaskRunningSentinel,
    ) -> Result<(), Box<dyn Error>>;
    fn task(self: Box<Self>) -> ResourceFut;
}

impl<T: sealed::ResourceBase<U>, const U: usize> NodeTrait for Node<T, U> {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn augment_args(&self, c: clap::Command) -> clap::Command {
        <T as sealed::ResourceBase<U>>::augment_args(c)
    }

    fn make(
        &self,
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut ArgMatches,
        stoppers: ShutdownSignalParticipantCreator,
        keepalive: TaskRunningSentinel,
    ) -> Result<(), Box<dyn Error>> {
        let _ = self.production.set(<T as sealed::ResourceBase<U>>::make(
            cx,
            arg_matches,
            stoppers,
            keepalive,
        )?);
        Ok(())
    }

    fn task(mut self: Box<Self>) -> ResourceFut {
        <T as sealed::ResourceBase<U>>::task(self.production.take().unwrap())
    }
}

struct NodeRelationship {
    parent: Option<usize>,
    child: usize,
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct RegisterContext<'a> {
    type_map: &'a mut HashMap<TypeId, usize>,
    parent: Option<usize>,
    nodes: &'a mut Vec<Box<dyn NodeTrait>>,
    relationships: &'a mut Vec<NodeRelationship>,
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct ProduceContext<'a> {
    type_map: HashMap<TypeId, usize>,
    nodes: &'a Vec<Box<dyn NodeTrait>>,
}

pub(crate) mod sealed {
    use super::{
        Arc, ArgMatches, Error, ProduceContext, RegisterContext, ResourceFut,
        ShutdownSignalParticipantCreator, TaskRunningSentinel,
    };

    pub trait ResourceBase<const T: usize>: Send + Sync + 'static {
        const NAME: &str;
        type Production;

        fn register_recursive(_: &mut RegisterContext<'_>) {}
        fn augment_args(c: clap::Command) -> clap::Command {
            c
        }
        fn make(
            cx: &mut ProduceContext<'_>,
            arg_matches: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            keepalive: TaskRunningSentinel,
        ) -> Result<Self::Production, Box<dyn Error>>;
        fn shared(re: &Self::Production) -> Arc<Self>;
        fn task(re: Self::Production) -> ResourceFut;
    }
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct Registrar<T> {
    _never_constructed: T,
}

impl<T> Registrar<T> {
    pub fn register<const U: usize>(cx: &mut RegisterContext<'_>)
    where
        T: sealed::ResourceBase<U>,
    {
        let me = TypeId::of::<T>();
        let next_i = cx.type_map.len();
        let (i, prune) = match cx.type_map.entry(me) {
            Entry::Vacant(e) => {
                e.insert(next_i);
                (next_i, false)
            }
            Entry::Occupied(e) => (*e.get(), true),
        };
        cx.relationships.push(NodeRelationship {
            parent: cx.parent,
            child: i,
        });
        if prune {
            return;
        }
        cx.nodes.push(Box::new(Node::<T, U>::default()));
        let parent = cx.parent.replace(i);
        <T as sealed::ResourceBase<U>>::register_recursive(cx);
        cx.parent = parent;
    }

    pub fn produce<const U: usize>(cx: &mut ProduceContext<'_>) -> Result<Arc<T>, Box<dyn Error>>
    where
        T: sealed::ResourceBase<U>,
    {
        let me = TypeId::of::<T>();
        let i = cx.type_map.get(&me).expect("dependency not mapped");
        let n: &dyn Any = cx.nodes[*i].as_ref();
        Ok(<T as sealed::ResourceBase<U>>::shared(
            n.downcast_ref::<Node<T, U>>()
                .expect("bad downcast")
                .production
                .get()
                .unwrap(),
        ))
    }
}

/// This trait expresses the collection of types of other resources that a
/// Resource depends on. It is also used to list the top-level resource
/// types at the roots of the [`Assembly`] graph.
///
/// This must be implemented on a struct containing zero or more fields of
/// type [`Arc<T>`] where T is a Resource. On that structure, the trait
/// should be derived.
///
/// ```
/// use comprehensive::{NoArgs, NoDependencies, ResourceDependencies};
/// use std::sync::Arc;
///
/// # struct OtherResource;
/// # impl comprehensive::v0::Resource for OtherResource {
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
/// **On the use of [`Arc`]**: During initialisation, a Resource might
/// reasonably desire mutable references to its dependencies, but this is
/// not available since the dependencies are supplied as [`Arc<T>`].
/// Resources can get around this by offering interior mutability APIs
/// (such as [`std::sync::Mutex`]) to their consumers. This was a design
/// tradeoff. An alternative design was considered where the dependencies
/// were supplied as `&'a mut T` (where `'a` is the lifetime of the
/// [`Assembly`]) but that arguably had worse issues since resources could
/// not retain those references outside of [`crate::v0::Resource::new`]
/// (since the reference needs to be available to another consumer).
/// Solutions are possible in case more longer-lived access is required,
/// but these are arguably not better than the [`Arc`] solution.
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
    shutdown_notify: ShutdownSignalForwarder,
    tasks: FuturesUnordered<ResourceFut>,
    names: Box<[Option<&'static str>]>,
    task_quits: crate::shutdown::TaskQuits,
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

fn active_list(names: &[Option<&'static str>]) -> String {
    let mut v = names.iter().filter_map(|n| *n).collect::<Vec<_>>();
    v.sort();
    v.join(", ")
}

pin_project! {
    struct TerminationSignal<T> {
        #[pin] signal_stream: Option<T>,
        shutdown_notify: Option<ShutdownSignalForwarder>,
    }
}

impl<T> TerminationSignal<T> {
    fn new(signal_stream: T, shutdown_notify: ShutdownSignalForwarder) -> Self {
        Self {
            signal_stream: Some(signal_stream),
            shutdown_notify: Some(shutdown_notify),
        }
    }
}

impl<T: Stream> Future for TerminationSignal<T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        loop {
            if let Some(s) = this.signal_stream.as_mut().as_pin_mut() {
                let _ = ready!(s.poll_next(cx));
                match this.shutdown_notify.take() {
                    Some(n) => {
                        log::warn!("SIGTERM received; shutting down");
                        n.propagate();
                        continue;
                    }
                    None => {
                        log::warn!("SIGTERM received again; quitting immediately.");
                    }
                }
            }
            this.signal_stream.set(None);
            return Poll::Ready(());
        }
    }
}

impl<T: Stream> futures::future::FusedFuture for TerminationSignal<T> {
    fn is_terminated(&self) -> bool {
        self.signal_stream.is_none()
    }
}

#[derive(Debug)]
struct CycleError {
    resources_in_cycle: Box<[&'static str]>,
}

impl CycleError {
    fn new(resources_in_cycle: impl Iterator<Item = &'static str>) -> Self {
        Self {
            resources_in_cycle: resources_in_cycle.collect::<Vec<_>>().into_boxed_slice(),
        }
    }
}

impl std::fmt::Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cycle in Resource graph, involving: {}",
            self.resources_in_cycle.join(", ")
        )
    }
}

impl std::error::Error for CycleError {}

fn build_order(
    ts: TopologicalSort<usize>,
    expect_len: usize,
) -> Result<Vec<usize>, impl Iterator<Item = usize>> {
    if expect_len == 0 {
        return Ok(Vec::new());
    }
    let mut build_order = ts.collect::<Vec<_>>();
    if build_order.len() == expect_len + 1 {
        // The last node in the build order should be the root.
        if build_order.pop().expect("always has size > 0") != expect_len {
            panic!("Dependency graph was built wrong: root was not sorted last");
        }
        Ok(build_order)
    } else {
        let mut not_in_cycle = FixedBitSet::with_capacity(expect_len - 1);
        for i in build_order {
            if i < not_in_cycle.len() {
                not_in_cycle.insert(i);
            }
        }
        not_in_cycle.toggle_range(..);
        Err(not_in_cycle.into_ones())
    }
}

struct AssemblySetup {
    nodes: Vec<Box<dyn NodeTrait>>,
    type_map: HashMap<TypeId, usize>,
    build_order: Vec<usize>,
    shutdown_notify: ShutdownSignal,
}

impl<T> Assembly<T>
where
    T: ResourceDependencies,
{
    fn setup() -> Result<AssemblySetup, CycleError> {
        let mut nodes = Vec::new();
        let mut type_map = HashMap::new();
        let mut relationships = Vec::new();
        let mut cx = RegisterContext {
            type_map: &mut type_map,
            parent: None,
            nodes: &mut nodes,
            relationships: &mut relationships,
        };
        T::register(&mut cx);

        let mut shutdown_notify = ShutdownSignal::new(nodes.len());
        let mut shutdown_notify_edit = shutdown_notify.get_mut().unwrap();
        for NodeRelationship { parent, child } in &relationships {
            shutdown_notify_edit.add_parent(*child, *parent);
        }
        let topo_sort = relationships
            .into_iter()
            .map(|NodeRelationship { parent, child }| {
                topological_sort::DependencyLink::from((parent.unwrap_or(nodes.len()), child))
            })
            .collect::<TopologicalSort<_>>();

        let build_order = build_order(topo_sort, nodes.len())
            .map_err(|e| CycleError::new(e.into_iter().map(|i| nodes[i].name())))?;

        Ok(AssemblySetup {
            nodes,
            type_map,
            build_order,
            shutdown_notify,
        })
    }

    /// Build a new [`Assembly`] from the given resources and all their
    /// transitive dependencies.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Self::new_from_argv(std::env::args_os())
    }

    /// Build a new [`Assembly`] from the given resources and all their
    /// transitive dependencies, with a given command line argv.
    /// Mostly for testing.
    pub fn new_from_argv<I, A>(argv: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = A>,
        A: Into<std::ffi::OsString> + Clone,
    {
        let AssemblySetup {
            nodes,
            type_map,
            build_order,
            shutdown_notify,
        } = Self::setup()?;

        let mut command = Some(clap::Command::new("Assembly"));
        for n in &nodes {
            let c = command.take().unwrap();
            command = Some(n.augment_args(c));
        }
        let mut arg_matches =
            GlobalArgs::augment_args(command.take().unwrap()).get_matches_from(argv);
        let global_args = GlobalArgs::from_arg_matches(&arg_matches)?;
        if global_args.write_graph_and_exit {
            Self::write_graph(&mut std::io::stdout());
            std::process::exit(0);
        }

        let mut cx = ProduceContext {
            type_map,
            nodes: &nodes,
        };
        let (task_quits, participants_iter) = shutdown_notify.into_monitors();
        let mut participants = participants_iter.map(Some).collect::<Vec<_>>();
        for i in build_order {
            let (notifier, participant_creator) = participants[i]
                .take()
                .expect("same index appears twice in build order");
            nodes[i].make(&mut cx, &mut arg_matches, participant_creator, notifier)?;
        }
        let top = T::produce(&mut cx)?;
        let (_, root_participant_iter) = participants
            .last_mut()
            .unwrap()
            .take()
            .expect("missing root participant");
        let mut root_participant = root_participant_iter.into_inner().unwrap();
        // The root participant should be immediately ready because nothing depends on it.
        let Poll::Ready(shutdown_notify) = Pin::new(&mut root_participant)
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
        else {
            panic!("graph construction bug: something depends on the root");
        };

        let names = nodes.iter().map(|n| Some(n.name())).collect();
        let tasks = nodes.into_iter().map(|n| n.task()).collect();

        Ok(Self {
            tasks,
            names,
            top,
            shutdown_notify,
            task_quits,
        })
    }

    /// Run an [`Assembly`] by invoking and awaiting every resource in the graph.
    ///
    /// Runs until either any Resource terminates with an error, a termination
    /// signal is received (and graceful shutdown is finished), or all
    /// resources terminate successfully. (Returns immediately on an empty
    /// graph.)
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        self.run_with_termination_signal(tokio_stream::wrappers::SignalStream::new(
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        ))
        .await
    }

    /// Run an [`Assembly`] by invoking and awaiting every resource in the graph.
    ///
    /// Callers should usually use [`Assembly::run`] instead, which installs a
    /// `SIGTERM` handler and then calls this with it.
    pub async fn run_with_termination_signal(
        self,
        termination_signal: impl Stream<Item = ()> + Unpin,
    ) -> Result<(), Box<dyn Error>> {
        let Self {
            mut tasks,
            shutdown_notify,
            mut names,
            mut task_quits,
            top: _,
        } = self;
        log::info!(
            "Comprehensive starting with {} resources: {}",
            names.len(),
            active_list(&names)
        );

        // Flush out all the initialisation work, including resources with empty
        // run methods.
        loop {
            let progress1 = match poll!(tasks.next()) {
                Poll::Ready(Some(Err(e))) => {
                    return Err(e);
                }
                Poll::Ready(Some(Ok(()))) => true,
                Poll::Ready(None) => false,
                Poll::Pending => false,
            };
            let progress2 = match poll!(task_quits.next()) {
                Poll::Ready(Some(i)) => {
                    let _ = names[i].take();
                    true
                }
                Poll::Ready(None) => false,
                Poll::Pending => false,
            };
            if tasks.is_terminated() || task_quits.is_terminated() {
                log::info!("After startup, no resources remain running. Quit.");
                return Ok(());
            }
            if !progress1 && !progress2 {
                break;
            }
        }

        // Blocking loop for the rest of time.
        log::info!(
            "After startup, {} resources are running: {}",
            task_quits.len(),
            active_list(&names)
        );
        let mut term = TerminationSignal::new(termination_signal, shutdown_notify);
        loop {
            futures::select! {
                task_result = tasks.next() => {
                    if let Some(result) = task_result {
                        if result.is_err() {
                            return result;
                        }
                    } else {
                        break;
                    }
                }
                maybe_quit = task_quits.next() => {
                    if let Some(i) = maybe_quit {
                        let _ = names[i].take();
                    } else {
                        break;
                    }
                }
                _ = term => {
                    break;
                }
            }
        }
        if !tasks.is_terminated() {
            // Return any errors immediately available.
            while let Poll::Ready(Some(r)) = poll!(tasks.next()) {
                if r.is_err() {
                    return r;
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
        let AssemblySetup {
            nodes,
            type_map: _,
            build_order: _,
            shutdown_notify,
        } = Self::setup().unwrap();

        writeln!(w, "digraph \"Assembly\" {{").unwrap();
        writeln!(w, "  top [shape=box]").unwrap();
        let node_count = nodes.len();
        for (i, n) in nodes.into_iter().enumerate() {
            writeln!(w, "  \"i-{}\" [label={:?}]", i, n.name(),).unwrap();
        }
        for (i, (_, e)) in shutdown_notify.into_monitors().1.enumerate() {
            let parent_label;
            let parent = if i == node_count {
                "top"
            } else {
                parent_label = format!("i-{}", i);
                &parent_label
            };
            for child in e.into_inner().unwrap().iter_children() {
                writeln!(w, "  \"{}\" -> \"i-{}\"", parent, child,).unwrap();
            }
        }
        writeln!(w, "}}").unwrap();
    }
}

/// Convenience type that can be used as the `Dependencies` associated
/// type on any leaf [`Resource`].
///
/// [`Resource`]: [`crate::v0::Resource`]
#[derive(ResourceDependencies)]
pub struct NoDependencies;

/// Convenience type that can be used as the `Args` associated type on
/// any [`Resource`] that takes no command line arguments.
///
/// [`Resource`]: [`crate::v0::Resource`]
#[derive(clap::Args, Debug, Default)]
#[group(skip)]
pub struct NoArgs {}

pub(crate) fn log_resource_result<T, U: std::fmt::Display>(r: &Result<T, U>, name: &str) {
    match r {
        Err(e) => {
            log::error!("{} failed: {}", name, e);
        }
        Ok(_) => {
            log::info!("{} exited successfully", name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::ShutdownSignalParticipant;
    use crate::testutil::TestExecutor;

    use atomic_take::AtomicTake;
    use regex::Regex;
    use std::ops::Deref;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct QuitInfo {
        expect_quit: Option<HashMap<&'static str, tokio::sync::oneshot::Receiver<()>>>,
    }

    static CONSTRUCT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static QUIT_REPORTER: std::sync::Mutex<QuitInfo> =
        std::sync::Mutex::new(QuitInfo { expect_quit: None });

    #[derive(Debug)]
    struct NoGood;

    impl std::fmt::Display for NoGood {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "no good")
        }
    }

    impl std::error::Error for NoGood {}

    trait TestResource: Send + Sync + Sized + 'static {
        type Dependencies: ResourceDependencies;
        const NAME: &str;
        fn new(_: Self::Dependencies) -> Result<Self, Box<dyn std::error::Error>>;
    }

    struct FailTask;

    impl Future for FailTask {
        type Output = Result<(), Box<dyn Error>>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Err(NoGood.into()))
        }
    }

    pin_project! {
        struct ReportTask {
            name: &'static str,
            #[pin] stopper: Option<ShutdownSignalParticipant>,
            #[pin] block: Option<tokio::sync::oneshot::Receiver<()>>,
            forwarder: Option<ShutdownSignalForwarder>,
            up: Option<TaskRunningSentinel>,
        }
    }

    impl Future for ReportTask {
        type Output = Result<(), Box<dyn Error>>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut this = self.project();
            if this.block.is_none() {
                if let Some(stopper) = this.stopper.as_mut().as_pin_mut() {
                    *this.forwarder = Some(ready!(stopper.poll(cx)));
                    let mut qi = QUIT_REPORTER.lock().unwrap();
                    let expect_quit = qi.expect_quit.as_mut().unwrap();
                    let Some(fut) = expect_quit.remove(this.name) else {
                        panic!(
                            "{} was signalled to quit but that was not (yet) expected",
                            this.name
                        );
                    };
                    this.block.set(Some(fut));
                }
            }
            if let Some(block) = this.block.as_mut().as_pin_mut() {
                let _ = ready!(block.poll(cx));
                this.block.set(None);
                if let Some(forwarder) = this.forwarder.take() {
                    forwarder.propagate();
                }
            }
            let _ = this.up.take();
            Poll::Ready(Ok(()))
        }
    }

    impl<T: TestResource> sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for T {
        const NAME: &str = T::NAME;
        type Production = (
            Arc<Self>,
            Option<ShutdownSignalParticipant>,
            TaskRunningSentinel,
        );

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            T::Dependencies::register(cx);
        }

        fn augment_args(c: clap::Command) -> clap::Command {
            if T::NAME == "Mid" {
                c.arg(
                    clap::Arg::new("count")
                        .long("count")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    clap::Arg::new("report")
                        .long("report")
                        .action(clap::ArgAction::SetTrue),
                )
            } else {
                c
            }
        }

        fn make(
            cx: &mut ProduceContext<'_>,
            arg_matches: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            up: TaskRunningSentinel,
        ) -> Result<Self::Production, Box<dyn Error>> {
            if arg_matches
                .get_one::<bool>("count")
                .copied()
                .unwrap_or_default()
            {
                CONSTRUCT_COUNT.fetch_add(1, Ordering::Release);
            }
            Ok((
                Arc::new(T::new(T::Dependencies::produce(cx)?)?),
                if arg_matches
                    .get_one::<bool>("report")
                    .copied()
                    .unwrap_or_default()
                {
                    stoppers.into_inner()
                } else {
                    None
                },
                up,
            ))
        }

        fn shared(re: &Self::Production) -> Arc<Self> {
            Arc::clone(&re.0)
        }

        fn task(
            p: (
                Arc<T>,
                Option<ShutdownSignalParticipant>,
                TaskRunningSentinel,
            ),
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            match p.1 {
                Some(stopper) => Box::pin(ReportTask {
                    stopper: Some(stopper),
                    name: T::NAME,
                    block: None,
                    forwarder: None,
                    up: Some(p.2),
                }),
                None => Box::pin(FailTask),
            }
        }
    }

    struct Leaf1 {}

    impl TestResource for Leaf1 {
        type Dependencies = NoDependencies;
        const NAME: &str = "Leaf1";

        fn new(_: NoDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self {})
        }
    }

    #[derive(Debug)]
    struct Leaf2 {}

    impl TestResource for Leaf2 {
        type Dependencies = NoDependencies;
        const NAME: &str = "Leaf2";

        fn new(_: NoDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self {})
        }
    }

    #[derive(ResourceDependencies)]
    struct MidDependencies(Arc<Leaf1>, Arc<Leaf2>);

    struct Mid {
        deps: MidDependencies,
    }

    impl TestResource for Mid {
        type Dependencies = MidDependencies;
        const NAME: &str = "Mid";

        fn new(deps: MidDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self { deps })
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies {
        mid: Arc<Mid>,
        l2: Arc<Leaf2>,
    }

    const EMPTY: &[std::ffi::OsString] = &[];

    #[test]
    fn correct_number_of_resources() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--count".into()];
        let before = CONSTRUCT_COUNT.load(Ordering::Acquire);
        let _assembly = Assembly::<TopDependencies>::new_from_argv(argv).expect("assembly");
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
        let re = Regex::new(r#".*"(i-[^"]+)".*label="([^"]+)".*"#).unwrap();
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
        let assembly = Assembly::<TopDependencies>::new_from_argv(EMPTY).unwrap();
        let leaf2_1 = Arc::deref(&assembly.top.mid.deps.1) as *const Leaf2;
        let leaf2_2 = Arc::deref(&assembly.top.l2) as *const Leaf2;
        assert_eq!(leaf2_1, leaf2_2);
        // Leaf1 only via Mid
        assert_eq!(Arc::strong_count(&assembly.top.mid.deps.0), 1);
        // Leaf2 also via top
        assert_eq!(Arc::strong_count(&assembly.top.mid.deps.1), 2);
    }

    #[derive(ResourceDependencies)]
    struct CyclicDependencies(Arc<CyclicResource>);

    #[derive(Debug)]
    struct CyclicResource {}

    impl TestResource for CyclicResource {
        type Dependencies = CyclicDependencies;
        const NAME: &str = "CyclicResource";

        fn new(d: CyclicDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            println!("{:?}", d.0); // silence "field is never read"
            Ok(Self {})
        }
    }

    #[test]
    fn cyclic_dependency1() {
        let Err(e) = Assembly::<CyclicDependencies>::new_from_argv(EMPTY) else {
            panic!("Should have detected a cycle");
        };
        assert!(e.is::<CycleError>());
    }

    #[derive(Debug)]
    struct CyclicResource1;

    impl TestResource for CyclicResource1 {
        type Dependencies = CyclicDependencies1;
        const NAME: &str = "CyclicResource1";

        fn new(_: CyclicDependencies1) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    #[derive(Debug)]
    struct CyclicResourceLeaf;

    impl TestResource for CyclicResourceLeaf {
        type Dependencies = NoDependencies;
        const NAME: &str = "CyclicResourceLeaf";

        fn new(_: NoDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    #[derive(ResourceDependencies)]
    struct CyclicDependencies2 {
        _cr1: Arc<CyclicResource1>,
        _crl: Arc<CyclicResourceLeaf>,
    }

    #[derive(Debug)]
    struct CyclicResource2;

    impl TestResource for CyclicResource2 {
        type Dependencies = CyclicDependencies2;
        const NAME: &str = "CyclicResource2";

        fn new(_: CyclicDependencies2) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    #[derive(ResourceDependencies)]
    struct CyclicDependencies1 {
        _cr2: Arc<CyclicResource2>,
    }

    #[test]
    fn cyclic_dependency2() {
        let Err(e) = Assembly::<CyclicDependencies2>::new_from_argv(EMPTY) else {
            panic!("Should have detected a cycle");
        };
        let mut cycle = e.downcast::<CycleError>().expect("CycleError");
        cycle.resources_in_cycle.sort();
        assert_eq!(
            cycle.resources_in_cycle,
            ["CyclicResource1", "CyclicResource2"].into()
        );
    }

    #[test]
    fn run_assembly() {
        let mut r = pin!(
            Assembly::<TopDependencies>::new_from_argv(EMPTY)
                .unwrap()
                .run_with_termination_signal(futures::stream::pending())
        );
        let mut e = TestExecutor::default();
        match e.poll(&mut r) {
            Poll::Ready(Err(e)) => {
                assert_eq!(e.to_string(), "no good");
            }
            other => {
                panic!("assembly await result: want error, got {:?}", other);
            }
        }
    }

    #[test]
    fn shutdown_order() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--report".into()];
        let assembly = Assembly::<TopDependencies>::new_from_argv(argv).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();

        if let Ok(mut qi) = QUIT_REPORTER.lock() {
            qi.expect_quit = Some(HashMap::new());
        }

        assert!(e.poll(&mut r).is_pending());

        // Quit from the top, expect only Mid to quit
        let (mid_tx, mid_rx) = tokio::sync::oneshot::channel();
        if let Ok(mut qi) = QUIT_REPORTER.lock() {
            let to_quit = qi.expect_quit.as_mut().unwrap();
            to_quit.insert("Mid", mid_rx);
        }
        let _ = tx.try_send(()).unwrap();

        assert!(e.poll(&mut r).is_pending());
        assert!(
            QUIT_REPORTER
                .lock()
                .unwrap()
                .expect_quit
                .as_ref()
                .unwrap()
                .is_empty()
        );

        // Allow Mid to disappear, Leaf1 and Leaf2 will then also quit.
        let (leaf1_tx, leaf1_rx) = tokio::sync::oneshot::channel();
        let (leaf2_tx, leaf2_rx) = tokio::sync::oneshot::channel();
        if let Ok(mut qi) = QUIT_REPORTER.lock() {
            let to_quit = qi.expect_quit.as_mut().unwrap();
            to_quit.insert("Leaf1", leaf1_rx);
            to_quit.insert("Leaf2", leaf2_rx);
        }
        std::mem::drop(mid_tx);

        assert!(e.poll(&mut r).is_pending());
        assert!(
            QUIT_REPORTER
                .lock()
                .unwrap()
                .expect_quit
                .as_ref()
                .unwrap()
                .is_empty()
        );

        // Allow the leaves to disappear, and that should be all.
        std::mem::drop(leaf1_tx);
        std::mem::drop(leaf2_tx);

        assert!(e.poll(&mut r).is_ready());
        assert!(
            QUIT_REPORTER
                .lock()
                .unwrap()
                .expect_quit
                .as_ref()
                .unwrap()
                .is_empty()
        );
    }

    struct RunUntilSignaled(AtomicTake<tokio::sync::oneshot::Sender<()>>);

    pin_project! {
        struct RunUntilSignaledTask {
            #[pin] test_signals_we_are_done: tokio::sync::oneshot::Receiver<()>,
            notifier: Option<TaskRunningSentinel>,
        }
    }

    impl Future for RunUntilSignaledTask {
        type Output = Result<(), Box<dyn Error>>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.as_mut().project();
            let _ = ready!(this.test_signals_we_are_done.poll(cx));
            let _ = this.notifier.take();
            Poll::Pending
        }
    }

    struct RunUntilSignaledProduction {
        shared: Arc<RunUntilSignaled>,
        task: RunUntilSignaledTask,
    }

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for RunUntilSignaled {
        const NAME: &str = "RunUntilSignaled";
        type Production = RunUntilSignaledProduction;

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            _: ShutdownSignalParticipantCreator,
            notifier: TaskRunningSentinel,
        ) -> Result<RunUntilSignaledProduction, Box<dyn Error>> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            Ok(RunUntilSignaledProduction {
                shared: Arc::new(RunUntilSignaled(AtomicTake::new(tx))),
                task: RunUntilSignaledTask {
                    test_signals_we_are_done: rx,
                    notifier: Some(notifier),
                },
            })
        }

        fn shared(re: &RunUntilSignaledProduction) -> Arc<RunUntilSignaled> {
            Arc::clone(&re.shared)
        }

        fn task(
            re: RunUntilSignaledProduction,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(re.task)
        }
    }

    #[derive(ResourceDependencies)]
    struct RunUntilSignaledTop {
        r: Arc<RunUntilSignaled>,
    }

    #[test]
    fn runs_until_resource_quits() {
        let assembly = Assembly::<RunUntilSignaledTop>::new().unwrap();
        let notify = assembly.top.r.0.take();
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        std::mem::drop(notify);
        assert!(e.poll(&mut r).is_ready());
    }

    #[tokio::test]
    async fn needs_2_sigterms() {
        let assembly = Assembly::<RunUntilSignaledTop>::new_from_argv(EMPTY).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        assert!(poll!(&mut r).is_pending());
        let _ = tx.send(()).await;
        // Does not quit after the first request.
        assert!(poll!(&mut r).is_pending());
        let _ = tx.send(()).await;
        // Does quit after the second.
        assert!(poll!(&mut r).is_ready());
    }

    #[derive(Default)]
    struct CleanShutdown(AtomicBool);

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for CleanShutdown {
        const NAME: &str = "CleanShutdown";
        type Production = (Arc<Self>, ShutdownSignalParticipant, TaskRunningSentinel);

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            term_signals: ShutdownSignalParticipantCreator,
            up: TaskRunningSentinel,
        ) -> Result<Self::Production, Box<dyn Error>> {
            Ok((
                Arc::new(CleanShutdown::default()),
                term_signals.into_inner().unwrap(),
                up,
            ))
        }

        fn shared(re: &Self::Production) -> Arc<CleanShutdown> {
            Arc::clone(&re.0)
        }

        fn task(
            (re, term_signal, up): Self::Production,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async move {
                let _keepalive = up;
                let _ = term_signal.await;
                re.0.store(true, Ordering::Release);
                Ok(())
            })
        }
    }

    #[derive(ResourceDependencies)]
    struct CleanShutdownTop(Arc<CleanShutdown>);

    #[test]
    fn clean_shutdown() {
        let assembly = Assembly::<CleanShutdownTop>::new_from_argv(EMPTY).unwrap();
        let shared = Arc::clone(&assembly.top.0);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
        assert!(shared.0.load(Ordering::Acquire));
    }
}
