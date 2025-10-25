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
use delegate::delegate;
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
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use topological_sort::TopologicalSort;
use tracing::{Level, error, info, instrument, span, warn};

use crate::dependencies::ResourceDependencies;
use crate::drop_stream::{DropStream, Sentinel};
use crate::matrix::DepMatrix;
use crate::shutdown::{ShutdownSignal, ShutdownSignalForwarder, ShutdownSignalParticipantCreator};

pub(crate) type ResourceFut = Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>>;

#[derive(Debug)]
enum ResourceInstantiationErrorUnderlying {
    Leaf(Box<dyn Error>),
    FailedDependencies(Vec<Rc<ResourceInstantiationError>>),
}

#[derive(Debug)]
struct ResourceInstantiationError {
    tracing_span: Option<tracing::Span>,
    node_name: Option<&'static str>,
    underlying: ResourceInstantiationErrorUnderlying,
}

impl std::fmt::Display for ResourceInstantiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Some required Resources could not be created:")?;
        self.fmt_problems(f, &mut Vec::new())
    }
}

impl std::error::Error for ResourceInstantiationError {}

impl ResourceInstantiationError {
    fn new(
        e: Box<dyn Error>,
        cx: &mut ProduceContext<'_>,
        node_name: Option<&'static str>,
        tracing_span: Option<tracing::Span>,
    ) -> Self {
        Self {
            tracing_span,
            node_name,
            underlying: match e.downcast::<ErrorIsInProduceContext>() {
                Ok(_) => ResourceInstantiationErrorUnderlying::FailedDependencies(std::mem::take(
                    &mut cx.make_errors,
                )),
                Err(e) => ResourceInstantiationErrorUnderlying::Leaf(e),
            },
        }
    }

    fn new_from_list(
        e: impl Iterator<Item = Rc<ResourceInstantiationError>>,
        node_name: Option<&'static str>,
    ) -> Self {
        Self {
            tracing_span: None,
            node_name,
            underlying: ResourceInstantiationErrorUnderlying::FailedDependencies(e.collect()),
        }
    }

    fn fmt_problems(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        chain: &mut Vec<&'static str>,
    ) -> std::fmt::Result {
        match self.underlying {
            ResourceInstantiationErrorUnderlying::Leaf(ref e) => {
                write!(f, "\n  ")?;
                if let Some(name) = self.node_name {
                    write!(f, "{}", name)?;
                }
                if !chain.is_empty() {
                    for (i, n) in chain.iter().rev().enumerate() {
                        if i == 0 {
                            write!(f, " (required by {}", n)?;
                        } else {
                            write!(f, " which is required by {}", n)?;
                        }
                    }
                    write!(f, ")")?;
                }
                write!(f, ": {}", e)?;
            }
            ResourceInstantiationErrorUnderlying::FailedDependencies(ref v) => {
                if let Some(name) = self.node_name {
                    chain.push(name);
                }
                for e in v {
                    e.fmt_problems(f, chain)?;
                }
                if self.node_name.is_some() {
                    chain.pop();
                }
            }
        }
        Ok(())
    }
}

struct Node<T: sealed::ResourceBase<U>, const U: usize> {
    production: OnceCell<Result<T::Production, Rc<ResourceInstantiationError>>>,
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
    fn register_as_traits(&self, cx: sealed::TraitRegisterContext<'_>);
    fn augment_args(&self, _: clap::Command) -> clap::Command;
    fn make(
        &self,
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut ArgMatches,
        stoppers: ShutdownSignalParticipantCreator,
        keepalive: MakeSentinel<'_>,
        dependency_test: sealed::DependencyTest,
    );
    fn task(self: Box<Self>) -> Option<ResourceFut>;
    fn created(&self) -> bool;
    fn error(&self) -> Option<&Rc<ResourceInstantiationError>>;
}

impl<T: sealed::ResourceBase<U>, const U: usize> NodeTrait for Node<T, U> {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn register_as_traits(&self, cx: sealed::TraitRegisterContext<'_>) {
        <T as sealed::ResourceBase<U>>::register_as_traits(cx)
    }

    fn augment_args(&self, c: clap::Command) -> clap::Command {
        <T as sealed::ResourceBase<U>>::augment_args(c)
    }

    fn make(
        &self,
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut ArgMatches,
        stoppers: ShutdownSignalParticipantCreator,
        keepalive: MakeSentinel<'_>,
        dependency_test: sealed::DependencyTest,
    ) {
        let span = span!(Level::INFO, "Comprehensive", resource = T::NAME);
        let _ = self.production.set(
            span.in_scope(|| {
                <T as sealed::ResourceBase<U>>::make(
                    cx,
                    arg_matches,
                    stoppers,
                    keepalive.make(),
                    dependency_test,
                )
            })
            .map_err(|e| {
                Rc::new(ResourceInstantiationError::new(
                    e,
                    cx,
                    Some(T::NAME),
                    Some(span),
                ))
            }),
        );
        cx.make_errors.clear();
    }

    fn task(mut self: Box<Self>) -> Option<ResourceFut> {
        self.production
            .take()
            .and_then(|p| p.ok().map(|p| <T as sealed::ResourceBase<U>>::task(p)))
    }

    fn created(&self) -> bool {
        matches!(self.production.get(), Some(Ok(_)))
    }

    fn error(&self) -> Option<&Rc<ResourceInstantiationError>> {
        self.production.get().and_then(|p| p.as_ref().err())
    }
}

struct NodeRelationship {
    parent: Option<usize>,
    child: usize,
}

struct TraitProduction(Box<dyn Any>);

impl TraitProduction {
    fn new<T: Any + ?Sized>() -> Self {
        Self(Box::new(Vec::<Arc<T>>::new()))
    }

    fn push<T: Any + ?Sized>(&mut self, item: Arc<T>) {
        self.0
            .downcast_mut::<Vec<Arc<T>>>()
            .expect("bad downcast")
            .push(item);
    }

    fn vec<T: Any + ?Sized>(&self) -> &Vec<Arc<T>> {
        self.0.downcast_ref::<Vec<Arc<T>>>().expect("bad downcast")
    }
}

struct TraitGraphNode(&'static str, usize);

impl TraitGraphNode {
    fn name(&self) -> &'static str {
        self.0
    }

    fn augment_args(&self, c: clap::Command) -> clap::Command {
        c
    }

    fn make(
        &self,
        _: &mut ProduceContext<'_>,
        _: &mut ArgMatches,
        _: ShutdownSignalParticipantCreator,
        _: MakeSentinel<'_>,
        _: sealed::DependencyTest,
    ) {
    }

    fn task(self) -> Option<ResourceFut> {
        None
    }

    fn created(&self) -> bool {
        false
    }

    fn error(&self) -> Option<&Rc<ResourceInstantiationError>> {
        None
    }
}

enum GraphNode {
    Resource(Box<dyn NodeTrait>),
    Trait(TraitGraphNode),
}

impl GraphNode {
    delegate! {
        to match self {
            Self::Resource(inner) => inner,
            Self::Trait(inner) => inner,
        } {
            fn name(&self) -> &'static str;
            fn augment_args(&self, c: clap::Command) -> clap::Command;
            fn make(
                &self,
                cx: &mut ProduceContext<'_>,
                arg_matches: &mut ArgMatches,
                stoppers: ShutdownSignalParticipantCreator,
                keepalive: MakeSentinel<'_>,
                dependency_test: sealed::DependencyTest,
            );
            fn task(self) -> Option<ResourceFut>;
            fn created(&self) -> bool;
            fn error(&self) -> Option<&Rc<ResourceInstantiationError>>;
        }
    }

    fn is_inert(&self) -> bool {
        match self {
            Self::Resource(_) => false,
            Self::Trait(_) => true,
        }
    }
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct RegisterContext<'a> {
    type_map: &'a mut HashMap<TypeId, usize>,
    parent: Option<usize>,
    nodes: &'a mut Vec<GraphNode>,
    relationships: &'a mut Vec<NodeRelationship>,
    next_trait_id: usize,
}

impl RegisterContext<'_> {
    pub fn require_trait<T: Any + ?Sized>(&mut self) {
        let me = TypeId::of::<T>();
        let next_i = self.type_map.len();
        let i = self.type_map.entry(me).or_insert_with(|| {
            self.nodes.push(GraphNode::Trait(TraitGraphNode(
                std::any::type_name::<T>(),
                self.next_trait_id,
            )));
            self.next_trait_id += 1;
            next_i
        });
        self.relationships.push(NodeRelationship {
            parent: self.parent,
            child: *i,
        });
    }

    fn internal_register<T, const U: usize, const DEP: bool>(&mut self)
    where
        T: sealed::ResourceBase<U>,
    {
        let me = TypeId::of::<T>();
        let next_i = self.type_map.len();
        let (i, prune) = match self.type_map.entry(me) {
            Entry::Vacant(e) => {
                e.insert(next_i);
                (next_i, false)
            }
            Entry::Occupied(e) => (*e.get(), true),
        };
        if DEP {
            self.relationships.push(NodeRelationship {
                parent: self.parent,
                child: i,
            });
        }
        if prune {
            return;
        }
        self.nodes
            .push(GraphNode::Resource(Box::new(Node::<T, U>::default())));
        let parent = self.parent.replace(i);
        <T as sealed::ResourceBase<U>>::register_recursive(self);
        self.parent = parent;
    }
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct ProduceContext<'a> {
    type_map: HashMap<TypeId, usize>,
    nodes: &'a Vec<GraphNode>,
    trait_productions: Box<[Option<TraitProduction>]>,
    dep_matrix: &'a DepMatrix,
    make_errors: Vec<Rc<ResourceInstantiationError>>,
}

impl ProduceContext<'_> {
    pub(crate) fn get_trait_i<T: Any + ?Sized>(&self, i: sealed::DependencyTest) -> Option<usize> {
        self.type_map
            .get(&TypeId::of::<T>())
            // Only if this resource has previously declared it exports this trait.
            .filter(|ti| self.dep_matrix.get_bit(**ti, i.0))
            .copied()
    }

    pub(crate) fn provide_as_trait<T: Any + ?Sized>(&mut self, i: usize, shared: Arc<T>) {
        if let GraphNode::Trait(TraitGraphNode(_, prod_i)) = self.nodes[i] {
            self.trait_productions[prod_i]
                .get_or_insert_with(|| TraitProduction::new::<T>())
                .push(shared);
        }
    }

    pub fn produce_trait<T: Any + ?Sized>(&self) -> Vec<Arc<T>> {
        if let Some(i) = self.type_map.get(&TypeId::of::<T>()) {
            if let GraphNode::Trait(TraitGraphNode(_, prod_i)) = self.nodes[*i] {
                return self.trait_productions[prod_i]
                    .as_ref()
                    .map(|v| v.vec())
                    .cloned()
                    .unwrap_or_default();
            }
        }
        Vec::new()
    }

    pub fn produce_trait_fallible<T: Any + ?Sized>(
        &self,
    ) -> Result<Vec<Arc<T>>, impl std::error::Error + 'static> {
        if let Some(i) = self.type_map.get(&TypeId::of::<T>()) {
            if let GraphNode::Trait(TraitGraphNode(_, prod_i)) = self.nodes[*i] {
                let maybe_v = self.trait_productions[prod_i].as_ref().map(|v| v.vec());
                let expect_count = self.dep_matrix.count_row(*i);
                let have_count = maybe_v.map(|v| v.len()).unwrap_or_default();
                if expect_count != have_count {
                    return Err(ResourceInstantiationError::new_from_list(
                        self.dep_matrix
                            .iter_row(*i)
                            .filter_map(|j| self.nodes[j].error().cloned()),
                        Some(self.nodes[*i].name()),
                    ));
                }
                return Ok(maybe_v.cloned().unwrap_or_default());
            }
        }
        Ok(Vec::new())
    }
}

pub(crate) mod sealed {
    use super::{
        Any, Arc, ArgMatches, Error, HashMap, NodeRelationship, ProduceContext, RegisterContext,
        ResourceFut, Sentinel, ShutdownSignalParticipantCreator, TypeId,
    };

    pub struct TraitRegisterContext<'a> {
        pub(super) type_map: &'a HashMap<TypeId, usize>,
        pub(super) relationships: &'a mut Vec<NodeRelationship>,
        pub(super) trait_provider: usize,
    }

    impl TraitRegisterContext<'_> {
        pub(crate) fn register_as_trait<T: Any + ?Sized>(&mut self) {
            if let Some(trait_i) = self.type_map.get(&TypeId::of::<T>()) {
                self.relationships.push(NodeRelationship {
                    parent: Some(*trait_i),
                    child: self.trait_provider,
                });
            }
        }
    }

    pub trait ResourceBase<const T: usize>: Send + Sync + 'static {
        const NAME: &str;
        type Production;

        fn register_recursive(_: &mut RegisterContext<'_>) {}
        fn register_as_traits(_: TraitRegisterContext<'_>) {}
        fn augment_args(c: clap::Command) -> clap::Command {
            c
        }
        fn make(
            cx: &mut ProduceContext<'_>,
            arg_matches: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            keepalive: Sentinel,
            dependency_test: DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>>;
        fn shared(re: &Self::Production) -> Arc<Self>;
        fn task(re: Self::Production) -> ResourceFut;
    }

    #[derive(Clone, Copy)]
    pub struct DependencyTest(pub(super) usize);
}

/// Opaque type used in the implementation of the [`ResourceDependencies`]
/// trait, which should be derived.
#[doc(hidden)]
pub struct Registrar<T> {
    _never_constructed: T,
}

#[derive(Debug)]
struct ErrorIsInProduceContext;

impl std::fmt::Display for ErrorIsInProduceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ErrorIsInProduceContext")
    }
}

impl std::error::Error for ErrorIsInProduceContext {}

impl<T> Registrar<T> {
    pub fn register<const U: usize>(cx: &mut RegisterContext<'_>)
    where
        T: sealed::ResourceBase<U>,
    {
        cx.internal_register::<T, U, true>()
    }

    pub fn register_without_dependency<const U: usize>(cx: &mut RegisterContext<'_>)
    where
        T: sealed::ResourceBase<U>,
    {
        cx.internal_register::<T, U, false>()
    }

    pub fn produce<const U: usize>(cx: &mut ProduceContext<'_>) -> Result<Arc<T>, Box<dyn Error>>
    where
        T: sealed::ResourceBase<U>,
    {
        let me = TypeId::of::<T>();
        let i = cx.type_map.get(&me).expect("dependency not mapped");
        let GraphNode::Resource(ref gn) = cx.nodes[*i] else {
            panic!("not a Resource");
        };
        let n: &dyn Any = gn.as_ref();
        Ok(<T as sealed::ResourceBase<U>>::shared(
            n.downcast_ref::<Node<T, U>>()
                .expect("bad downcast")
                .production
                .get()
                .unwrap()
                .as_ref()
                .map_err(|e| {
                    // Move the error into an accumulator so we can collect all
                    // the errors associated with producing the current set of
                    // dependencies, then return a marker error that will
                    // later signal us to return all the errors in bulk.
                    cx.make_errors.push(Rc::clone(e));
                    ErrorIsInProduceContext
                })?,
        ))
    }
}

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
    task_quits: DropStream,
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
                        warn!("SIGTERM received; shutting down");
                        n.propagate();
                        continue;
                    }
                    None => {
                        warn!("SIGTERM received again; quitting immediately.");
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
    root_id: usize,
) -> Result<Vec<usize>, impl Iterator<Item = usize>> {
    if expect_len == 1 {
        return Ok(Vec::new());
    }
    let mut build_order = ts.collect::<Vec<_>>();
    if build_order.len() == expect_len {
        // The last node in the build order should be the root.
        if build_order.pop().expect("always has size > 0") != root_id {
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
    nodes: Vec<GraphNode>,
    type_map: HashMap<TypeId, usize>,
    build_order: Vec<usize>,
    dep_matrix: DepMatrix,
    n_traits: usize,
}

struct ConsumeReady<'a, T>(&'a mut T);

impl<T> Iterator for ConsumeReady<'_, T>
where
    T: Stream + futures::stream::FusedStream + Unpin,
{
    type Item = T::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self
            .0
            .poll_next_unpin(&mut Context::from_waker(std::task::Waker::noop()))
        {
            Poll::Ready(x) => x,
            Poll::Pending => None,
        }
    }
}

struct MakeSentinel<'a>(&'a mut crate::drop_stream::Builder, usize);

impl MakeSentinel<'_> {
    fn make(self) -> Sentinel {
        self.0.make_sentinel(self.1).expect("take notifier")
    }
}

fn log_failures(
    msg: &str,
    task_quits: &mut DropStream,
    nodes: &[GraphNode],
) -> impl Iterator<Item = usize> {
    ConsumeReady(task_quits).inspect(move |failed_i| {
        if let Some(e) = nodes[*failed_i].error() {
            let _enter = e.tracing_span.as_ref().map(tracing::Span::enter);
            warn!("{} failed to initialise: {}", msg, e);
        }
    })
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
            next_trait_id: 0,
        };
        T::register(&mut cx);
        let n_traits = cx.next_trait_id;

        for (i, gn) in nodes.iter().enumerate() {
            if let GraphNode::Resource(n) = gn {
                n.register_as_traits(sealed::TraitRegisterContext {
                    type_map: &type_map,
                    relationships: &mut relationships,
                    trait_provider: i,
                });
            }
        }

        let root_id = nodes.len();
        let mut dep_matrix = DepMatrix::new(root_id + 1, root_id);
        for NodeRelationship { parent, child } in relationships {
            dep_matrix.set_bit(parent.unwrap_or(root_id), child);
        }
        dep_matrix.with_incref(root_id, |m| m.remove_unreferenced());
        let topo_sort = dep_matrix
            .edges()
            .map(topological_sort::DependencyLink::from)
            .collect::<TopologicalSort<_>>();

        let build_order = build_order(topo_sort, dep_matrix.n_live_rows(), root_id)
            .map_err(|e| CycleError::new(e.into_iter().map(|i| nodes[i].name())))?;

        Ok(AssemblySetup {
            nodes,
            type_map,
            build_order,
            dep_matrix,
            n_traits,
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
        let span = span!(Level::INFO, "Assembly::new");
        let enter = span.enter();
        let AssemblySetup {
            nodes,
            type_map,
            build_order,
            mut dep_matrix,
            n_traits,
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
            trait_productions: std::iter::repeat_n((), n_traits).map(|_| None).collect(),
            dep_matrix: &dep_matrix,
            make_errors: Vec::new(),
        };
        let participants_iter =
            ShutdownSignal::new(nodes.iter().map(|gn| gn.is_inert()), &dep_matrix);
        let mut task_quits_gen = crate::drop_stream::Builder::new(nodes.len());
        let mut participants = participants_iter.collect::<Vec<_>>();
        for i in build_order {
            let participant_creator = participants[i]
                .take()
                .expect("same index appears twice or deleted index in build order");
            nodes[i].make(
                &mut cx,
                &mut arg_matches,
                participant_creator,
                MakeSentinel(&mut task_quits_gen, i),
                sealed::DependencyTest(i),
            );
        }
        let mut task_quits = task_quits_gen.into_stream();
        let top = T::produce(&mut cx).map_err(|e| {
            let _ = log_failures("Resource", &mut task_quits, &nodes).last();
            let e = ResourceInstantiationError::new(e, &mut cx, None, None);
            error!("Failed to construct assembly: {}", e);
            e
        })?;
        let root_participant_iter = participants
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

        for failed_i in log_failures("Optional resource", &mut task_quits, &nodes) {
            shutdown_notify.completely_unref(failed_i, &mut dep_matrix);
        }

        let names = nodes
            .iter()
            .map(|n| if n.created() { Some(n.name()) } else { None })
            .collect();
        drop(enter);
        let tasks = nodes.into_iter().filter_map(|n| n.task()).collect();
        shutdown_notify.accept_dep_matrix(dep_matrix);
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
    #[instrument(name = "Assembly", skip_all)]
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
        info!(
            "Comprehensive starting with {} resources: {}",
            names.iter().filter(|n| n.is_some()).count(),
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
                info!("After startup, no resources remain running. Quit.");
                return Ok(());
            }
            if !progress1 && !progress2 {
                break;
            }
        }

        // Blocking loop for the rest of time.
        info!(
            "After startup, {} resources are running: {}",
            names.iter().filter(|n| n.is_some()).count(),
            active_list(&names)
        );
        let mut term = TerminationSignal::new(termination_signal, shutdown_notify);
        loop {
            futures::select! {
                task_result = tasks.next() => {
                    if let Some(result) = task_result {
                        result?;
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
                r?;
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
            dep_matrix,
            n_traits: _,
        } = Self::setup().unwrap();

        writeln!(w, "digraph \"Assembly\" {{").unwrap();
        writeln!(w, "  top [shape=box]").unwrap();
        let node_count = nodes.len();
        for (i, n) in nodes.into_iter().enumerate() {
            let shape = match n {
                GraphNode::Resource(_) => "",
                GraphNode::Trait(_) => " shape=hexagon",
            };
            writeln!(w, "  \"i-{}\" [label={:?}{}]", i, n.name(), shape).unwrap();
        }
        for (from_i, to_i) in dep_matrix.edges() {
            let parent_label;
            let parent = if from_i == node_count {
                "top"
            } else {
                parent_label = format!("i-{}", from_i);
                &parent_label
            };
            writeln!(w, "  \"{}\" -> \"i-{}\"", parent, to_i).unwrap();
        }
        writeln!(w, "}}").unwrap();
    }
}

/// Convenience type that can be used as the `Args` associated type on
/// any [`Resource`] that takes no command line arguments.
///
/// [`Resource`]: [`crate::v0::Resource`]
#[derive(clap::Args, Debug, Default)]
#[group(skip)]
pub struct NoArgs {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnyResource;
    use crate::dependencies::sealed::AvailableResource;
    use crate::dependencies::{MayFail, NoDependencies};
    use crate::shutdown::ShutdownSignalParticipant;
    use crate::testutil::TestExecutor;

    use atomic_take::AtomicTake;
    use regex::Regex;
    use std::marker::PhantomData;
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
            up: Option<Sentinel>,
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
        type Production = (Arc<Self>, Option<ShutdownSignalParticipant>, Sentinel);

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            T::Dependencies::register(cx);
        }

        fn augment_args(c: clap::Command) -> clap::Command {
            if T::NAME == "Mid"
                || T::NAME == "FailsToCreate"
                || T::NAME == "Fail1"
                || T::NAME == "FailLeaveOrphan"
            {
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
            up: Sentinel,
            _: sealed::DependencyTest,
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
            p: (Arc<T>, Option<ShutdownSignalParticipant>, Sentinel),
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

    pub struct TestResourceProvider<T>(std::marker::PhantomData<T>);

    impl<T: TestResource> AvailableResource for TestResourceProvider<T> {
        type ResourceType = T;

        fn register(cx: &mut RegisterContext) {
            Registrar::<T>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<T>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<T>, Box<dyn std::error::Error>> {
            Registrar::<T>::produce(cx)
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

    impl AnyResource for Leaf1 {
        type Target = TestResourceProvider<Self>;
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

    impl AnyResource for Leaf2 {
        type Target = TestResourceProvider<Self>;
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

    impl AnyResource for Mid {
        type Target = TestResourceProvider<Self>;
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

    fn fix_graph_for_comparison<'a>(
        digraph: &'a str,
        names: &'a mut HashMap<String, String>,
    ) -> Vec<(&'a str, &'a str)> {
        let lines = digraph.split("\n").collect::<Vec<_>>();

        // The node ids are opaque. Let's map them.
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
        edges
    }

    #[test]
    fn correct_graph() {
        let mut output = Vec::new();
        Assembly::<TopDependencies>::write_graph(&mut output);
        let digraph = String::from_utf8(output).unwrap();
        let mut names = HashMap::new();
        let edges = fix_graph_for_comparison(&digraph, &mut names);
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
    struct CyclicDependencies(#[old_style] Arc<CyclicResource>);

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

    impl AnyResource for CyclicResource1 {
        type Target = TestResourceProvider<Self>;
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
        #[old_style]
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

    impl AnyResource for CyclicResource2 {
        type Target = TestResourceProvider<Self>;
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

    #[derive(Debug)]
    struct FailsToCreate;

    #[derive(ResourceDependencies)]
    struct FailsToCreateDependencies(Arc<Leaf1>);

    impl TestResource for FailsToCreate {
        type Dependencies = FailsToCreateDependencies;
        const NAME: &str = "FailsToCreate";

        fn new(d: FailsToCreateDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            let _ = d.0;
            Err("init problem 1".into())
        }
    }

    impl AnyResource for FailsToCreate {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(Debug)]
    struct AlsoFailsToCreate;

    impl TestResource for AlsoFailsToCreate {
        type Dependencies = NoDependencies;
        const NAME: &str = "AlsoFailsToCreate";

        fn new(_: NoDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Err("init problem 2".into())
        }
    }

    impl AnyResource for AlsoFailsToCreate {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(Debug)]
    struct DependsOnFailsToCreate;

    #[derive(ResourceDependencies)]
    struct DependsOnFailsToCreateDependencies {
        _d0: Arc<FailsToCreate>,
        _d1: Arc<AlsoFailsToCreate>,
    }

    impl TestResource for DependsOnFailsToCreate {
        type Dependencies = DependsOnFailsToCreateDependencies;
        const NAME: &str = "DependsOnFailsToCreate";

        fn new(_: DependsOnFailsToCreateDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    impl AnyResource for DependsOnFailsToCreate {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct DependsOnFailsToCreateTop {
        _d0: Arc<DependsOnFailsToCreate>,
    }

    #[test]
    fn depends_on_fails_to_create() {
        let Err(e) = Assembly::<DependsOnFailsToCreateTop>::new_from_argv(EMPTY) else {
            panic!("Should have failed to create");
        };
        let make_error = e
            .downcast::<ResourceInstantiationError>()
            .expect("ResourceInstantiationError");
        let ResourceInstantiationError {
            tracing_span: None,
            node_name: None,
            underlying: ResourceInstantiationErrorUnderlying::FailedDependencies(v),
        } = *make_error
        else {
            panic!("unexpected error: {:?}", make_error);
        };
        assert_eq!(v.len(), 1, "expect 2 error: {:?}", v);
        let ResourceInstantiationError {
            tracing_span: Some(_),
            node_name: Some(n),
            underlying: ResourceInstantiationErrorUnderlying::FailedDependencies(ref d),
        } = *v[0]
        else {
            panic!("unexpected error: {:?}", v[0]);
        };
        assert_eq!(n, "DependsOnFailsToCreate");
        assert_eq!(d.len(), 2, "expect 2 error: {:?}", d);
        let ResourceInstantiationError {
            tracing_span: Some(_),
            node_name: Some(n1),
            underlying: ResourceInstantiationErrorUnderlying::Leaf(ref l1),
        } = *d[0]
        else {
            panic!("unexpected error: {:?}", d[0]);
        };
        assert_eq!(n1, "FailsToCreate");
        assert_eq!(l1.to_string(), "init problem 1");
        let ResourceInstantiationError {
            tracing_span: Some(_),
            node_name: Some(n2),
            underlying: ResourceInstantiationErrorUnderlying::Leaf(ref l2),
        } = *d[1]
        else {
            panic!("unexpected error: {:?}", d[1]);
        };
        assert_eq!(n2, "AlsoFailsToCreate");
        assert_eq!(l2.to_string(), "init problem 2");
    }

    #[derive(Debug)]
    struct HalfDependsOnFailsToCreate;

    #[derive(ResourceDependencies)]
    struct HalfDependsOnFailsToCreateDependencies {
        _d0: Arc<FailsToCreate>,
        _d1: Option<Arc<AlsoFailsToCreate>>,
    }

    impl TestResource for HalfDependsOnFailsToCreate {
        type Dependencies = HalfDependsOnFailsToCreateDependencies;
        const NAME: &str = "HalfDependsOnFailsToCreate";

        fn new(
            _: HalfDependsOnFailsToCreateDependencies,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    impl AnyResource for HalfDependsOnFailsToCreate {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct HalfDependsOnFailsToCreateTop {
        _d0: Arc<HalfDependsOnFailsToCreate>,
    }

    #[test]
    fn half_depends_on_fails_to_create() {
        let Err(e) = Assembly::<HalfDependsOnFailsToCreateTop>::new_from_argv(EMPTY) else {
            panic!("Should have failed to create");
        };
        let make_error = e
            .downcast::<ResourceInstantiationError>()
            .expect("ResourceInstantiationError");
        let ResourceInstantiationError {
            tracing_span: None,
            node_name: None,
            underlying: ResourceInstantiationErrorUnderlying::FailedDependencies(v),
        } = *make_error
        else {
            panic!("unexpected error: {:?}", make_error);
        };
        assert_eq!(v.len(), 1, "expect 2 error: {:?}", v);
        let ResourceInstantiationError {
            tracing_span: Some(_),
            node_name: Some(n),
            underlying: ResourceInstantiationErrorUnderlying::FailedDependencies(ref d),
        } = *v[0]
        else {
            panic!("unexpected error: {:?}", v[0]);
        };
        assert_eq!(n, "HalfDependsOnFailsToCreate");
        assert_eq!(d.len(), 1, "expect 1 error: {:?}", d);
        let ResourceInstantiationError {
            tracing_span: Some(_),
            node_name: Some(n1),
            underlying: ResourceInstantiationErrorUnderlying::Leaf(ref l1),
        } = *d[0]
        else {
            panic!("unexpected error: {:?}", d[0]);
        };
        assert_eq!(n1, "FailsToCreate");
        assert_eq!(l1.to_string(), "init problem 1");
    }

    #[derive(Debug)]
    struct DependsOptionallyOnFailsToCreate;

    #[derive(ResourceDependencies)]
    struct DependsOptionallyOnFailsToCreateDependencies {
        _d0: Option<Arc<FailsToCreate>>,
        _d1: Option<Arc<AlsoFailsToCreate>>,
    }

    impl TestResource for DependsOptionallyOnFailsToCreate {
        type Dependencies = DependsOptionallyOnFailsToCreateDependencies;
        const NAME: &str = "DependsOptionallyOnFailsToCreate";

        fn new(
            _: DependsOptionallyOnFailsToCreateDependencies,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    impl AnyResource for DependsOptionallyOnFailsToCreate {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct DependsOptionallyOnFailsToCreateTop {
        _d0: Arc<DependsOptionallyOnFailsToCreate>,
    }

    #[test]
    fn depends_optionally_on_fails_to_create() {
        let a = Assembly::<DependsOptionallyOnFailsToCreateTop>::new_from_argv(EMPTY).unwrap();
        let edges = a
            .shutdown_notify
            .edges()
            .map(|(i, j)| (a.names.get(i), a.names.get(j)))
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), 1);
        let Some((None, Some(Some(x)))) = edges.into_iter().next() else {
            panic!("wrong edge");
        };
        assert_eq!(*x, "DependsOptionallyOnFailsToCreate");
        let mut r = pin!(a.run_with_termination_signal(futures::stream::pending()));
        let mut e = TestExecutor::default();
        match e.poll(&mut r) {
            Poll::Ready(Err(e)) => {
                assert_eq!(e.to_string(), "no good");
            }
            x => {
                panic!("run fail: {:?}", x);
            }
        }
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
            notifier: Option<Sentinel>,
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
            notifier: Sentinel,
            _: sealed::DependencyTest,
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

    impl AvailableResource for RunUntilSignaled {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for RunUntilSignaled {
        type Target = Self;
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
        type Production = (Arc<Self>, ShutdownSignalParticipant, Sentinel);

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            term_signals: ShutdownSignalParticipantCreator,
            up: Sentinel,
            _: sealed::DependencyTest,
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

    impl AvailableResource for CleanShutdown {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for CleanShutdown {
        type Target = Self;
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

    struct Fail2;

    impl TestResource for Fail2 {
        type Dependencies = NoDependencies;
        const NAME: &str = "Fail2";

        fn new(_: NoDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            Err("fail2".into())
        }
    }

    impl AnyResource for Fail2 {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct Fail1Dependencies(Option<Arc<Fail2>>);

    struct Fail1;

    impl TestResource for Fail1 {
        type Dependencies = Fail1Dependencies;
        const NAME: &str = "Fail1";

        fn new(d: Fail1Dependencies) -> Result<Self, Box<dyn std::error::Error>> {
            assert!(d.0.is_none());
            Err("fail1".into())
        }
    }

    impl AnyResource for Fail1 {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct FailFailTop(Option<Arc<Fail1>>);

    #[test]
    fn optfail_depends_on_optfail() {
        let assembly = Assembly::<FailFailTop>::new_from_argv(EMPTY).unwrap();
        assert!(assembly.top.0.is_none());
    }

    struct InertResource;

    struct InertResourceProduction {
        shared: Arc<InertResource>,
        _keepalive: Sentinel,
        stopper: ShutdownSignalParticipant,
    }

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for InertResource {
        const NAME: &str = "InertResource";
        type Production = InertResourceProduction;

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            sentinel: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<InertResourceProduction, Box<dyn Error>> {
            Ok(InertResourceProduction {
                shared: Arc::new(Self),
                _keepalive: sentinel,
                stopper: stoppers.into_inner().unwrap(),
            })
        }

        fn shared(re: &InertResourceProduction) -> Arc<Self> {
            Arc::clone(&re.shared)
        }

        fn task(
            re: InertResourceProduction,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async move {
                re.stopper.await.propagate();
                Ok(())
            })
        }
    }

    impl AvailableResource for InertResource {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for InertResource {
        type Target = Self;
    }

    struct FailLeaveOrphan;

    #[derive(ResourceDependencies)]
    struct FailLeaveOrphanDependencies(Arc<InertResource>);

    impl TestResource for FailLeaveOrphan {
        type Dependencies = FailLeaveOrphanDependencies;
        const NAME: &str = "FailLeaveOrphan";

        fn new(d: FailLeaveOrphanDependencies) -> Result<Self, Box<dyn std::error::Error>> {
            let _ = d.0;
            Err("fail leave orphan".into())
        }
    }

    impl AnyResource for FailLeaveOrphan {
        type Target = TestResourceProvider<Self>;
    }

    #[derive(ResourceDependencies)]
    struct FailOrphanTop(Option<Arc<FailLeaveOrphan>>);

    #[tokio::test]
    async fn optfail_leaves_orphan() {
        let assembly = Assembly::<FailOrphanTop>::new_from_argv(EMPTY).unwrap();
        let _ = assembly.top.0;
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        assert!(poll!(&mut r).is_ready());
    }

    trait TestTrait {}

    trait NobodyImplements {}

    trait NobodyInterested {}

    #[derive(ResourceDependencies)]
    struct RequiresDynDependencies(Vec<Arc<dyn TestTrait>>, Vec<Arc<dyn NobodyImplements>>);

    struct RequiresDyn(usize, usize);

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for RequiresDyn {
        const NAME: &str = "RequiresDyn";
        type Production = (Arc<Self>, ShutdownSignalParticipant, Sentinel);

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            RequiresDynDependencies::register(cx);
        }

        fn make(
            cx: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            up: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>> {
            let deps = RequiresDynDependencies::produce(cx)?;
            Ok((
                Arc::new(RequiresDyn(deps.0.len(), deps.1.len())),
                stoppers.into_inner().unwrap(),
                up,
            ))
        }

        fn shared(p: &Self::Production) -> Arc<Self> {
            Arc::clone(&p.0)
        }

        fn task(
            p: Self::Production,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async move {
                p.1.await.propagate();
                Ok(())
            })
        }
    }

    impl AvailableResource for RequiresDyn {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for RequiresDyn {
        type Target = Self;
    }

    #[derive(ResourceDependencies)]
    struct RequiresDynMayFailDependencies(
        MayFail<Vec<Arc<dyn TestTrait>>>,
        #[may_fail] Vec<Arc<dyn NobodyImplements>>,
    );

    struct RequiresDynMayFail(usize, usize);

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for RequiresDynMayFail {
        const NAME: &str = "RequiresDynMayFail";
        type Production = (Arc<Self>, ShutdownSignalParticipant, Sentinel);

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            RequiresDynMayFailDependencies::register(cx);
        }

        fn make(
            cx: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            up: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>> {
            let deps = RequiresDynMayFailDependencies::produce(cx)?;
            Ok((
                Arc::new(RequiresDynMayFail(deps.0.len(), deps.1.len())),
                stoppers.into_inner().unwrap(),
                up,
            ))
        }

        fn shared(p: &Self::Production) -> Arc<Self> {
            Arc::clone(&p.0)
        }

        fn task(
            p: Self::Production,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async move {
                p.1.await.propagate();
                Ok(())
            })
        }
    }

    impl AvailableResource for RequiresDynMayFail {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for RequiresDynMayFail {
        type Target = Self;
    }

    struct ProvidesDyn;

    impl TestTrait for ProvidesDyn {}

    impl NobodyInterested for ProvidesDyn {}

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for ProvidesDyn {
        const NAME: &str = "ProvidesDyn";
        type Production = (Arc<Self>, ShutdownSignalParticipant, Sentinel);

        fn register_as_traits(mut cx: sealed::TraitRegisterContext<'_>) {
            cx.register_as_trait::<dyn TestTrait>();
            cx.register_as_trait::<dyn NobodyInterested>();
        }

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            CleanShutdownTop::register(cx);
        }

        fn make(
            cx: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            stoppers: ShutdownSignalParticipantCreator,
            up: Sentinel,
            dt: sealed::DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>> {
            let _ = CleanShutdownTop::produce(cx)?;
            let shared = Arc::new(ProvidesDyn);

            if let Some(i) = cx.get_trait_i::<dyn TestTrait>(dt) {
                let shared2 = Arc::clone(&shared);
                let alias: Arc<dyn TestTrait> = shared2;
                cx.provide_as_trait(i, alias);
            }

            if let Some(i) = cx.get_trait_i::<dyn NobodyInterested>(dt) {
                let shared2 = Arc::clone(&shared);
                let alias: Arc<dyn NobodyInterested> = shared2;
                cx.provide_as_trait(i, alias);
            }

            Ok((shared, stoppers.into_inner().unwrap(), up))
        }

        fn shared(p: &Self::Production) -> Arc<Self> {
            Arc::clone(&p.0)
        }

        fn task(
            p: Self::Production,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async move {
                p.1.await.propagate();
                Ok(())
            })
        }
    }

    impl AvailableResource for ProvidesDyn {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for ProvidesDyn {
        type Target = Self;
    }

    struct AlsoProvidesDyn;

    impl TestTrait for AlsoProvidesDyn {}

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for AlsoProvidesDyn {
        const NAME: &str = "AlsoProvidesDyn";
        type Production = (Arc<Self>, Sentinel);

        fn register_as_traits(mut cx: sealed::TraitRegisterContext<'_>) {
            cx.register_as_trait::<dyn TestTrait>();
        }

        fn make(
            cx: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            _: ShutdownSignalParticipantCreator,
            up: Sentinel,
            dt: sealed::DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>> {
            let shared = Arc::new(AlsoProvidesDyn);
            if let Some(i) = cx.get_trait_i::<dyn TestTrait>(dt) {
                let shared2 = Arc::clone(&shared);
                let alias: Arc<dyn TestTrait> = shared2;
                cx.provide_as_trait(i, alias);
            }
            Ok((shared, up))
        }

        fn shared(p: &Self::Production) -> Arc<Self> {
            Arc::clone(&p.0)
        }

        fn task(
            _: Self::Production,
        ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            Box::pin(async { Ok(()) })
        }
    }

    impl AvailableResource for AlsoProvidesDyn {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for AlsoProvidesDyn {
        type Target = Self;
    }

    struct ProvidesDynButFails;

    impl TestTrait for ProvidesDynButFails {}

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for ProvidesDynButFails {
        const NAME: &str = "ProvidesDynButFails";
        type Production = ();

        fn register_as_traits(mut cx: sealed::TraitRegisterContext<'_>) {
            cx.register_as_trait::<dyn TestTrait>();
        }

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            _: ShutdownSignalParticipantCreator,
            _: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<Self::Production, Box<dyn Error>> {
            Err("ProvidesDynButFails".into())
        }

        fn shared(_: &()) -> Arc<Self> {
            unreachable!();
        }

        fn task(_: ()) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            unreachable!();
        }
    }

    impl AvailableResource for ProvidesDynButFails {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for ProvidesDynButFails {
        type Target = Self;
    }

    #[derive(ResourceDependencies)]
    struct RequiresDynTop(Arc<RequiresDyn>, Arc<ProvidesDyn>, Arc<AlsoProvidesDyn>);

    #[test]
    fn dyn_resource() {
        let assembly = Assembly::<RequiresDynTop>::new_from_argv(EMPTY).unwrap();
        let requires_dyn = Arc::clone(&assembly.top.0);
        assert_eq!(requires_dyn.0, 2);
        assert_eq!(requires_dyn.1, 0);
        let _ = Arc::clone(&assembly.top.1);
        let _ = Arc::clone(&assembly.top.2);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
    }

    #[test]
    fn correct_graph_with_dyn() {
        let mut output = Vec::new();
        Assembly::<RequiresDynTop>::write_graph(&mut output);
        let digraph = String::from_utf8(output).unwrap();
        let mut names = HashMap::new();
        let edges = fix_graph_for_comparison(&digraph, &mut names);
        assert_eq!(
            edges,
            vec![
                ("ProvidesDyn", "CleanShutdown"),
                (
                    "RequiresDyn",
                    "dyn comprehensive::assembly::tests::NobodyImplements"
                ),
                (
                    "RequiresDyn",
                    "dyn comprehensive::assembly::tests::TestTrait"
                ),
                (
                    "dyn comprehensive::assembly::tests::TestTrait",
                    "AlsoProvidesDyn"
                ),
                (
                    "dyn comprehensive::assembly::tests::TestTrait",
                    "ProvidesDyn"
                ),
                ("top", "AlsoProvidesDyn"),
                ("top", "ProvidesDyn"),
                ("top", "RequiresDyn"),
            ]
        );
    }

    #[derive(ResourceDependencies)]
    struct RequiresFailingDynTop {
        _d0: Arc<RequiresDyn>,
        _d1: PhantomData<ProvidesDyn>,
        _d2: PhantomData<ProvidesDynButFails>,
    }

    #[test]
    fn dyn_fail_resource() {
        let a = Assembly::<RequiresFailingDynTop>::new_from_argv(EMPTY);
        assert!(a.is_err());
    }

    #[derive(ResourceDependencies)]
    struct RequiresFailingDynMayFailTop {
        d0: Arc<RequiresDynMayFail>,
        _d1: PhantomData<ProvidesDyn>,
        _d2: PhantomData<ProvidesDynButFails>,
    }

    #[test]
    fn dyn_fail_may_failresource() {
        let a = Assembly::<RequiresFailingDynMayFailTop>::new_from_argv(EMPTY).unwrap();
        let requires_dyn = a.top.d0;
        assert_eq!(requires_dyn.0, 1);
        assert_eq!(requires_dyn.1, 0);
    }

    struct Ant;
    struct Dec;
    trait AntTrait {}
    trait DecTrait {}
    impl AntTrait for Ant {}
    impl DecTrait for Dec {}

    #[derive(ResourceDependencies)]
    struct AntDependencies(#[allow(dead_code)] Vec<Arc<dyn DecTrait>>);

    #[derive(ResourceDependencies)]
    struct DecDependencies(#[allow(dead_code)] Vec<Arc<dyn AntTrait>>);

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for Ant {
        const NAME: &str = "Ant";
        type Production = ();

        fn register_as_traits(mut cx: sealed::TraitRegisterContext<'_>) {
            cx.register_as_trait::<dyn AntTrait>();
        }

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            AntDependencies::register(cx);
        }

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            _: ShutdownSignalParticipantCreator,
            _: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<(), Box<dyn Error>> {
            unreachable!();
        }

        fn shared(_: &()) -> Arc<Self> {
            unreachable!();
        }

        fn task(_: ()) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            unreachable!();
        }
    }

    impl AvailableResource for Ant {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for Ant {
        type Target = Self;
    }

    impl sealed::ResourceBase<{ crate::ResourceVariety::Test as usize }> for Dec {
        const NAME: &str = "Dec";
        type Production = ();

        fn register_as_traits(mut cx: sealed::TraitRegisterContext<'_>) {
            cx.register_as_trait::<dyn DecTrait>();
        }

        fn register_recursive(cx: &mut RegisterContext<'_>) {
            DecDependencies::register(cx);
        }

        fn make(
            _: &mut ProduceContext<'_>,
            _: &mut ArgMatches,
            _: ShutdownSignalParticipantCreator,
            _: Sentinel,
            _: sealed::DependencyTest,
        ) -> Result<(), Box<dyn Error>> {
            unreachable!();
        }

        fn shared(_: &()) -> Arc<Self> {
            unreachable!();
        }

        fn task(_: ()) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
            unreachable!();
        }
    }

    impl AvailableResource for Dec {
        type ResourceType = Self;

        fn register(cx: &mut RegisterContext) {
            Registrar::<Self>::register(cx);
        }

        fn register_without_dependency(cx: &mut RegisterContext) {
            Registrar::<Self>::register_without_dependency(cx);
        }

        fn produce(cx: &mut ProduceContext) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
            Registrar::<Self>::produce(cx)
        }
    }

    impl AnyResource for Dec {
        type Target = Self;
    }

    #[derive(ResourceDependencies)]
    struct AntDecDependencies(#[allow(dead_code)] Arc<Ant>, #[allow(dead_code)] Arc<Dec>);

    #[test]
    fn cyclic_trait_resources() {
        let Err(e) = Assembly::<AntDecDependencies>::new_from_argv(EMPTY) else {
            panic!("Should have detected a cycle");
        };
        let _ = e.downcast::<CycleError>().expect("CycleError");
    }

    #[derive(ResourceDependencies)]
    struct PhantomIncludeNothingConsumes {
        _unused: PhantomData<ProvidesDyn>,
    }

    #[test]
    fn phantom_include_nothing_consumes_graph() {
        let mut output = Vec::new();
        Assembly::<PhantomIncludeNothingConsumes>::write_graph(&mut output);
        let digraph = String::from_utf8(output).unwrap();
        let mut names = HashMap::new();
        let edges = fix_graph_for_comparison(&digraph, &mut names);
        assert_eq!(edges, vec![],);
    }

    #[test]
    fn phantom_include_nothing_consumes_run() {
        let assembly = Assembly::<PhantomIncludeNothingConsumes>::new_from_argv(EMPTY).unwrap();
        assert_eq!(assembly.names.len(), 2);
        assert!(assembly.names[0].is_none());
        assert!(assembly.names[1].is_none());
        assert!(assembly.tasks.is_empty());
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_ready());
    }

    #[derive(ResourceDependencies)]
    struct PhantomIncludeSomethingConsumes {
        _unused1: PhantomData<ProvidesDyn>,
        _unused2: Arc<RequiresDyn>,
    }

    #[test]
    fn phantom_include_something_consumes() {
        let mut output = Vec::new();
        Assembly::<PhantomIncludeSomethingConsumes>::write_graph(&mut output);
        let digraph = String::from_utf8(output).unwrap();
        let mut names = HashMap::new();
        let edges = fix_graph_for_comparison(&digraph, &mut names);
        assert_eq!(
            edges,
            vec![
                ("ProvidesDyn", "CleanShutdown"),
                (
                    "RequiresDyn",
                    "dyn comprehensive::assembly::tests::NobodyImplements"
                ),
                (
                    "RequiresDyn",
                    "dyn comprehensive::assembly::tests::TestTrait"
                ),
                (
                    "dyn comprehensive::assembly::tests::TestTrait",
                    "ProvidesDyn"
                ),
                ("top", "RequiresDyn"),
            ],
        );
    }
}
