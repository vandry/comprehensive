//! Implementations of the [`Resource`] form the nodes of a directed acyclic
//! graph formed by a Comprehensive [`Assembly`] and represent a
//! component of a running stack, such as an HTTP serving instance, an
//! individual gRPC service, a provider for a backend such as a database,
//! and so on.
//!
//! Each resource can express what other resources it needs to do its work
//! and can have an implementation in the form of a shared API its
//! dependants may consume, or a unit of work, or both.
//!
//! This module hosts the soon-to-be default and recommended version of the
//! [`Resource`] trait. The earlier, development version was [`crate::v0`].
//! If it is found to be inadequate in the future and not possible to adapt,
//! it could be superceded by `v2`, however this is not anticipated. In any
//! case, resources of different versions can co-exist in the same assembly.
//!
//! [`Assembly`]: crate::Assembly

use clap::{Args, FromArgMatches};
use pin_project_lite::pin_project;
use std::error::Error;
use std::future::{Future, IntoFuture};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use crate::ResourceDependencies;
use crate::assembly::sealed::{DependencyTest, ResourceBase, TraitRegisterContext};
use crate::assembly::{ProduceContext, RegisterContext, ResourceFut};
use crate::dependencies::sealed::AvailableResource;
use crate::drop_stream::Sentinel;
use crate::shutdown::{ShutdownSignalParticipant, ShutdownSignalParticipantCreator};

/// [`Future`] returned by [`AssemblyRuntime::self_stop`] which resolves when
/// the [`Assembly`] has received a shutdown signal and the sequence of
/// orderly shutdown has reached this [`Resource`].
///
/// [`Assembly`]: crate::Assembly
pub struct StopSignal(ShutdownSignalParticipant);

impl Future for StopSignal {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.get_mut().0).poll(cx).map(|_| ())
    }
}

/// Model for a pair of asynchronous tasks: one to run first and until there
/// is an external indication to stop and another one to run instead after
/// that. For use with [`AssemblyRuntime::set_task_with_cleanup`].
///
/// Usage:
///
/// ```
/// use comprehensive::v1::{AssemblyRuntime, Resource, TaskWithCleanup, resource};
/// use std::sync::Arc;
///
/// struct NeedsToTakeActionOnShutdownTask {
///     private_state: i32,
/// }
///
/// impl TaskWithCleanup for NeedsToTakeActionOnShutdownTask {
///     #[allow(refining_impl_trait)]
///     async fn main_task(&mut self) -> Result<(), std::convert::Infallible> {
///         loop {
///             // THIS CODE MUST BE CANCEL-SAFE
///             // [...]
///         }
///     }
///
///     #[allow(refining_impl_trait)]
///     async fn cleanup(self) -> Result<(), std::convert::Infallible> {
///         // [...]
///         Ok(())
///     }
/// }
///
/// struct NeedsToTakeActionOnShutdown;
///
/// #[resource]
/// impl Resource for NeedsToTakeActionOnShutdown {
///     fn new(
///         _: comprehensive::NoDependencies,
///         a: comprehensive::NoArgs,
///         api: &mut AssemblyRuntime<'_>,
///     ) -> Result<Arc<Self>, std::convert::Infallible> {
///         api.set_task_with_cleanup(NeedsToTakeActionOnShutdownTask {
///             private_state: 42,
///         });
///         Ok(Arc::new(Self))
///     }
/// }
/// ```
pub trait TaskWithCleanup: Sized + Send + 'static {
    /// Main task from a main+cleanup pair. This task runs when the assembly
    /// first starts running and continues either until it returns or until
    /// a signal to shut down the assembly is received and all of the resources
    /// that depend on this one have already shut down.
    ///
    /// This task must be cancel-safe because it will be dropped immediately
    /// when it is time to run the cleanup task instead!
    ///
    /// If this returns an error then the entire [`Assembly`] will exit.
    ///
    /// [`Assembly`]: crate::Assembly
    fn main_task(&mut self) -> impl Future<Output = Result<(), impl Error + 'static>> + Send;

    /// Cleanup task from a main+cleanup pair. This task runs after the
    /// assembly has received a shutdown signal and the main task has been
    /// dropped. It should do work necessary to sanitise state before quitting
    /// but should not count on being allowed to run for too long.
    ///
    /// If the main task returns successfully before any shutdown signal is
    /// received then we assume there is no cleanup required, and this will
    /// not run at all.
    ///
    /// If this returns an error then the entire [`Assembly`] will exit.
    ///
    /// [`Assembly`]: crate::Assembly
    fn cleanup(self) -> impl Future<Output = Result<(), impl Error + 'static>> + Send;
}

/// Interface for interacting with an [`Assembly`] when
/// [`Resource::new`] is called.
///
/// [`Assembly`]: crate::Assembly
pub struct AssemblyRuntime<'a> {
    stoppers: Option<&'a mut ShutdownSignalParticipantCreator>,
    task: Option<Box<dyn Task>>,
}

impl AssemblyRuntime<'_> {
    /// Change the Resource's task execution mode from the default auto-stop
    /// mode to self-stop mode.
    ///
    /// In the default auto-stop mode, the task will cease execution (the
    /// Future will no longer be polled) as soon as the [`Assembly`] is
    /// requested to stop (e.g. by `SIGTERM`) and the signal has percolated
    /// down the dependency graph such that all resources that depend on
    /// this one have already stopped. This mode is suitable for resources
    /// that need to take no special actions at shutdown.
    ///
    /// If this method is called, self-stop mode will be used instead. When
    /// the conditions described above are reached, this resource's task
    /// will continue running, although it will be expected to start
    /// executing cleanup or shutdown actions and thereafter quit promptly
    /// (by resolving to `Ok(())`). To enable the task to find out when it
    /// is time to do this, this method returns a [`Future`] that resolves
    /// at that time.
    ///
    /// ## Panics
    ///
    /// This panics if called more than once.
    ///
    /// [`Assembly`]: crate::Assembly
    pub fn self_stop(&mut self) -> StopSignal {
        StopSignal(
            self.stoppers
                .take()
                .expect("self_stop called more than once")
                .next()
                .unwrap(),
        )
    }

    /// Configure an asynchronous task to run in connection with this
    /// [`Resource`]. Usually this is either a background task of some kind
    /// required to make the resource's functionality work for its consumers,
    /// or a piece of application logic.
    ///
    /// If called more than once, the arguments from all but the last call are
    /// discarded. If not called at all, then no task will run.
    ///
    /// If the task resolves to an error, the entire [`Assembly`] stops
    /// immediately, returning that error.
    ///
    /// If the task resolves successfully, the assembly continues running
    /// until there are no tasks left running or it receives a shutdown signal.
    ///
    /// Usually tasks are given as [`Future`]s and indeed often as naked
    /// `async { }` blocks. However if [`IntoFuture`] is implemented directly,
    /// it is guaranteed that [`IntoFuture::into_future`] is called after
    /// all resources in the assembly have been constructed and before any
    /// of their tasks have been polled.
    ///
    /// [`Assembly`]: crate::Assembly
    pub fn set_task<F>(&mut self, task: F)
    where
        F: IntoFuture<Output = Result<(), Box<dyn Error>>> + Send + 'static,
        F::IntoFuture: Send,
    {
        self.task = Some(Box::new(TaskImpl(task)));
    }

    /// Configure a main asynchronous task and a shutdown handler to run in
    /// connection with this [`Resource`]. The main task will run until the
    /// [`Assembly`] is signalled to shut down, at which time the cleanup task
    /// will run instead.
    ///
    /// The pair of tasks are given as 2 methods on a trait. Mutable state
    /// can be shared between the 2 tasks by storing it in the object that
    /// implements the trait.
    ///
    /// This is a convenience method. The same effect can be achieved with
    /// the use of [`AssemblyRuntime::self_stop`] and
    /// [`AssemblyRuntime::set_task`] with a task that switches
    /// modes upon receiving the shutdown notification.
    ///
    /// [`Assembly`]: crate::Assembly
    pub fn set_task_with_cleanup<T: TaskWithCleanup>(&mut self, task: T) {
        self.task = Some(Box::new(TaskWithCleanupImpl(task)));
    }
}

#[doc(hidden)]
pub struct TraitInstallerProduce<'a, 'b, 'c, R> {
    cx: &'a mut ProduceContext<'c>,
    shared: &'b Arc<R>,
    dependency_test: DependencyTest,
}

#[doc(hidden)]
pub enum TraitInstaller<'a, 'b, 'c, R> {
    Register(TraitRegisterContext<'b>),
    Produce(TraitInstallerProduce<'a, 'b, 'c, R>),
}

impl<R> TraitInstaller<'_, '_, '_, R> {
    pub fn offer<T, F>(&mut self, factory: F)
    where
        T: std::any::Any + ?Sized,
        F: FnOnce(&Arc<R>) -> Arc<T>,
    {
        match self {
            Self::Register(cx) => cx.register_as_trait::<T>(),
            Self::Produce(installer) => {
                if let Some(trait_i) = installer.cx.get_trait_i::<T>(installer.dependency_test) {
                    installer
                        .cx
                        .provide_as_trait(trait_i, factory(installer.shared));
                }
            }
        }
    }
}

/// The main unit of work in an [`Assembly`] and the trait common to each
/// of the nodes in its DAG.
///
/// There is an attribute macro [`resource`] which can be attached to
/// implementations of this trait which will automatically derive the
/// definitions of all the associated types and constant so that the only
/// thing that needs to be supplied is the `new` method.
///
/// [`Assembly`]: crate::Assembly
pub trait Resource: Send + Sync + Sized + 'static {
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

    /// Type of error returned by `new`. If returned, the creation of the
    /// whole assembly will be aborted.
    type CreationError: Into<Box<dyn Error + 'static>>;

    /// The name of this resource. Used in logs and resource graph
    /// diagnostics.
    const NAME: &str;

    /// Construct a resource of this type. Called while the graph of all
    /// resources is built in [`crate::Assembly::new`].
    ///
    /// Returns an `Arc<Self>` which will be made available to other
    /// resources that depend on this one.
    ///
    /// The [`AssemblyRuntime`] argument may be used to install a task
    /// (a unit of work) that will run in connection with this resource.
    fn new(
        deps: Self::Dependencies,
        args: Self::Args,
        api: &mut AssemblyRuntime<'_>,
    ) -> Result<Arc<Self>, Self::CreationError>;

    /// Make this resource available to other resources that declare a
    /// dependency on a trait object. This is used for one resource to
    /// collect dependencies on all of the other resources in the
    /// assembly that share some property (by implementins a trait).
    /// By default, a resource is available to be declared as a
    /// dependency under its own name only, not as any `dyn Trait`.
    ///
    /// To make this resource available as one or more trait objects,
    /// see the [`resource`] attribute macro (which will supply an
    /// appropriate definition for this method).
    ///
    /// To declare a dependency on a resource that makes itself available
    /// in this way, see the [`ResourceDependencies`] derive macro.
    ///
    /// [`ResourceDependencies`]: crate::ResourceDependencies
    fn provide_as_trait<'a>(_: &'a mut TraitInstaller<'_, 'a, '_, Self>) {}
}

/// An attribute macro that can be used to automatically supply definitions
/// for the associated types and constant of a [`Resource`].
///
/// Any definitions which are already supplied will not be synthesised. This
/// can be useful for example for overriding `NAME`.
///
/// An attribute like `#[export(dyn Trait)]` may be given zero or more times.
/// This will cause the resource to be requestable as a dependency by other
/// resources under its identity as an implementor of the given trait in
/// addition to its own concrete type. See [`ResourceDependencies`] for
/// how other resources can declare such a dependency.
///
/// ```
/// # struct SomeType;
/// # type AA = comprehensive::NoDependencies;
/// # type BB = comprehensive::NoArgs;
/// # type CC = std::convert::Infallible;
/// # use std::sync::Arc;
/// # trait SharedTraitForResourcesOfSomeKind {}
/// use comprehensive::v1::{AssemblyRuntime, Resource, resource};
///
/// impl SharedTraitForResourcesOfSomeKind for SomeType {}
///
/// #[resource]
/// #[export(dyn SharedTraitForResourcesOfSomeKind)]  // Optional
/// impl Resource for SomeType {
///     // All of these definitions are synthesised since the types can all
///     // be inferred from the signature of the `new` method and the type name.
///
///     // type Dependencies = AA;
///     // type Args = BB;
///     // type CreationError = CC;
///     // const NAME: &str = "SomeType";
///
///     fn new(_: AA, _: BB, _: &mut AssemblyRuntime<'_>) -> Result<Arc<Self>, CC> {
///         // [...]
/// #       Ok(Arc::new(Self))
///     }
/// }
/// ```
///
/// [`ResourceDependencies`]: crate::ResourceDependencies
pub use comprehensive_macros::v1resource as resource;

pin_project! {
    struct TaskInner<F> {
        #[pin] fut: F,
        keepalive: Sentinel,
    }
}

pin_project! {
    struct AutoStopTask<F> {
        #[pin] stopper: ShutdownSignalParticipant,
        #[pin] inner: Option<TaskInner<F>>,
    }
}

pin_project! {
    struct SelfStopTask<F> {
        #[pin] stopper: ShutdownSignalParticipant,
        #[pin] inner: Option<TaskInner<F>>,
    }
}

impl<F> AutoStopTask<F> {
    fn new<T>(task: T, stopper: ShutdownSignalParticipant, keepalive: Sentinel) -> Self
    where
        T: IntoFuture<IntoFuture = F>,
    {
        Self {
            inner: Some(TaskInner {
                fut: task.into_future(),
                keepalive,
            }),
            stopper,
        }
    }
}

impl<F> Future for AutoStopTask<F>
where
    F: Future<Output = Result<(), Box<dyn Error>>>,
{
    type Output = Result<(), Box<dyn Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if let Poll::Ready(forwarder) = this.stopper.poll(cx) {
            // In AutoStop mode we can quit immediately when we receive a quit
            // request. Propagate the shutdown and forget the inner task.
            forwarder.propagate();
            this.inner.set(None);
            return Poll::Ready(Ok(()));
        }
        // Drive the inner Future but it doesn't determine the outcome.
        if let Some(inner) = this.inner.as_mut().as_pin_mut() {
            if let Poll::Ready(r) = inner.project().fut.poll(cx) {
                this.inner.set(None);
                if r.is_err() {
                    return Poll::Ready(r);
                }
            }
        }
        Poll::Pending
    }
}

impl<F> SelfStopTask<F> {
    fn new<T>(task: T, stopper: ShutdownSignalParticipant, keepalive: Sentinel) -> Self
    where
        T: IntoFuture<IntoFuture = F>,
    {
        Self {
            inner: Some(TaskInner {
                fut: task.into_future(),
                keepalive,
            }),
            stopper,
        }
    }
}

impl<F> Future for SelfStopTask<F>
where
    F: Future<Output = Result<(), Box<dyn Error>>>,
{
    type Output = Result<(), Box<dyn Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        // Drive the inner Future, ignoring the stop signal.
        if let Some(inner) = this.inner.as_mut().as_pin_mut() {
            if let Poll::Ready(r) = inner.project().fut.poll(cx) {
                this.inner.set(None);
                if r.is_err() {
                    return Poll::Ready(r);
                }
            } else {
                return Poll::Pending;
            }
        }
        // Only after that is done, clean up.
        if let Poll::Ready(forwarder) = this.stopper.poll(cx) {
            forwarder.propagate();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

trait Task: Send {
    fn into_task(
        self: Box<Self>,
        stopper: ShutdownSignalParticipant,
        keepalive: Sentinel,
        auto_stop: bool,
    ) -> ResourceFut;
}

struct TaskImpl<T>(T);

impl<T> Task for TaskImpl<T>
where
    T: IntoFuture<Output = Result<(), Box<dyn Error>>> + Send,
    T::IntoFuture: Send + 'static,
{
    fn into_task(
        self: Box<Self>,
        stopper: ShutdownSignalParticipant,
        keepalive: Sentinel,
        auto_stop: bool,
    ) -> ResourceFut {
        if auto_stop {
            Box::pin(AutoStopTask::new(self.0, stopper, keepalive))
        } else {
            Box::pin(SelfStopTask::new(self.0, stopper, keepalive))
        }
    }
}

struct TaskWithCleanupImpl<T>(T);

enum CleanupFollowup {
    MainExited,
    ShutdownRequested(crate::shutdown::ShutdownSignalForwarder, Sentinel),
}

pin_project! {
    struct TaskWithCleanupMain<'a, F> {
        stopper: Pin<&'a mut ShutdownSignalParticipant>,
        #[pin] main_task: F,
        keepalive: Option<Sentinel>,
    }
}

impl<F, E> Future for TaskWithCleanupMain<'_, F>
where
    F: Future<Output = Result<(), E>>,
    E: 'static,
{
    type Output = Result<CleanupFollowup, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        Poll::Ready(match this.stopper.as_mut().poll(cx) {
            Poll::Ready(forwarder) => Ok(CleanupFollowup::ShutdownRequested(
                forwarder,
                this.keepalive.take().unwrap(),
            )),
            Poll::Pending => ready!(this.main_task.poll(cx)).map(|()| CleanupFollowup::MainExited),
        })
    }
}

impl<T> Task for TaskWithCleanupImpl<T>
where
    T: TaskWithCleanup,
{
    fn into_task(
        mut self: Box<Self>,
        stopper: ShutdownSignalParticipant,
        keepalive: Sentinel,
        _: bool,
    ) -> ResourceFut {
        Box::pin(async move {
            let mut stopper = pin!(stopper);
            let a = TaskWithCleanupMain {
                stopper: stopper.as_mut(),
                main_task: self.0.main_task(),
                keepalive: Some(keepalive),
            }
            .await?;
            match a {
                CleanupFollowup::MainExited => stopper.await,
                CleanupFollowup::ShutdownRequested(forwarder, _keepalive) => {
                    self.0.cleanup().await?;
                    forwarder
                }
            }
            .propagate();
            Ok(())
        })
    }
}

mod private {
    pub struct ResourceProduction<T> {
        pub(super) shared: std::sync::Arc<T>,
        pub(super) task: Option<Box<dyn super::Task>>,
        pub(super) stopper: super::ShutdownSignalParticipant,
        pub(super) keepalive: super::Sentinel,
        pub(super) auto_stop: bool,
    }
}

impl<T: Resource> ResourceBase<{ crate::ResourceVariety::V1 as usize }> for T {
    const NAME: &str = T::NAME;
    type Production = private::ResourceProduction<T>;

    fn register_recursive(cx: &mut RegisterContext<'_>) {
        T::Dependencies::register(cx);
    }

    fn augment_args(c: clap::Command) -> clap::Command {
        T::Args::augment_args(c)
    }

    fn register_as_traits(cx: TraitRegisterContext<'_>) {
        let mut installer = TraitInstaller::Register(cx);
        T::provide_as_trait(&mut installer);
    }

    fn make(
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut clap::ArgMatches,
        mut stoppers: ShutdownSignalParticipantCreator,
        keepalive: Sentinel,
        dependency_test: DependencyTest,
    ) -> Result<Self::Production, Box<dyn Error>> {
        let deps = T::Dependencies::produce(cx)?;
        let args = T::Args::from_arg_matches(arg_matches)?;
        let mut api = AssemblyRuntime {
            stoppers: Some(&mut stoppers),
            task: None,
        };
        let shared = T::new(deps, args, &mut api).map_err(Into::into)?;
        let mut installer = TraitInstaller::Produce(TraitInstallerProduce {
            cx,
            shared: &shared,
            dependency_test,
        });
        T::provide_as_trait(&mut installer);
        Ok(private::ResourceProduction {
            shared,
            task: api.task,
            auto_stop: api.stoppers.is_some(),
            stopper: stoppers.into_inner().unwrap(),
            keepalive,
        })
    }

    fn shared(p: &Self::Production) -> Arc<T> {
        Arc::clone(&p.shared)
    }

    fn task(
        p: Self::Production,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
        match p.task {
            Some(t) => t.into_task(p.stopper, p.keepalive, p.auto_stop),
            None => Box::pin(async move {
                p.stopper.await.propagate();
                Ok(())
            }),
        }
    }
}

#[doc(hidden)]
pub struct ResourceProvider<T>(std::marker::PhantomData<T>);

impl<T: Resource> AvailableResource for ResourceProvider<T> {
    type ResourceType = T;

    fn register(cx: &mut RegisterContext) {
        crate::assembly::Registrar::<T>::register(cx);
    }

    fn register_without_dependency(cx: &mut RegisterContext) {
        crate::assembly::Registrar::<T>::register_without_dependency(cx);
    }

    fn produce(cx: &mut ProduceContext) -> Result<Arc<T>, Box<dyn std::error::Error>> {
        crate::assembly::Registrar::<T>::produce(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestExecutor;
    use crate::{Assembly, NoArgs, NoDependencies};

    use atomic_take::AtomicTake;
    use futures::TryFutureExt;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use try_lock::TryLock;

    const EMPTY: &[std::ffi::OsString] = &[];

    struct Fails;

    #[resource]
    impl Resource for Fails {
        fn new(
            _: NoDependencies,
            _: NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            api.set_task(std::future::ready(Err("no good")).err_into());
            Ok(Arc::new(Self))
        }
    }

    #[derive(ResourceDependencies)]
    struct FailDependencies {
        _f: Arc<Fails>,
    }

    #[test]
    fn assembly_fails() {
        let mut r = pin!(
            Assembly::<FailDependencies>::new_from_argv(EMPTY)
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

    struct QuitMonitor(AtomicBool);

    #[resource]
    impl Resource for QuitMonitor {
        fn new(
            _: NoDependencies,
            _: NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let shared = Arc::new(Self(AtomicBool::default()));
            let sentinel = Arc::clone(&shared);
            let stop = api.self_stop();
            api.set_task(async move {
                stop.await;
                sentinel.0.store(true, Ordering::Release);
                Ok(())
            });
            Ok(shared)
        }
    }

    struct TestAutoStop {
        skip_task: bool,
        leaf: Arc<QuitMonitor>,
    }

    #[derive(ResourceDependencies)]
    struct TestAutoStopDependencies(Arc<QuitMonitor>);

    #[derive(clap::Args)]
    #[group(skip)]
    struct TestAutoStopArgs {
        #[arg(long)]
        skip_task: bool,
    }

    #[resource]
    impl Resource for TestAutoStop {
        fn new(
            d: TestAutoStopDependencies,
            a: TestAutoStopArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            if !a.skip_task {
                api.set_task(std::future::pending());
            }
            Ok(Arc::new(Self {
                leaf: d.0,
                skip_task: a.skip_task,
            }))
        }
    }

    #[derive(ResourceDependencies)]
    struct TestAutoStopTopDependencies(Arc<TestAutoStop>);

    #[test]
    fn no_task() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--skip-task".into()];
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let assembly = Assembly::<TestAutoStopTopDependencies>::new_from_argv(argv).unwrap();
        let tas = Arc::clone(&assembly.top.0);
        assert!(tas.skip_task);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();

        // Steady state: nothing.
        assert!(e.poll(&mut r).is_pending());
        assert!(!tas.leaf.0.load(Ordering::Acquire));

        let _ = tx.try_send(()).unwrap();
        // Quit signal: received and propagated.
        assert!(e.poll(&mut r).is_ready());
        assert!(tas.leaf.0.load(Ordering::Acquire));
    }

    #[test]
    fn auto_stop() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let assembly = Assembly::<TestAutoStopTopDependencies>::new_from_argv(EMPTY).unwrap();
        let tas = Arc::clone(&assembly.top.0);
        assert!(!tas.skip_task);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();

        // Steady state: nothing.
        assert!(e.poll(&mut r).is_pending());
        assert!(!tas.leaf.0.load(Ordering::Acquire));

        let _ = tx.try_send(()).unwrap();
        // Quit signal: received and propagated.
        assert!(e.poll(&mut r).is_ready());
        assert!(tas.leaf.0.load(Ordering::Acquire));
    }

    struct TestSelfStop {
        quit_requested: TryLock<Option<tokio::sync::oneshot::Sender<()>>>,
        leaf: Arc<QuitMonitor>,
    }

    #[derive(ResourceDependencies)]
    struct TestSelfStopDependencies(Arc<QuitMonitor>);

    #[resource]
    impl Resource for TestSelfStop {
        fn new(
            d: TestSelfStopDependencies,
            _: NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let shared = Arc::new(Self {
                quit_requested: TryLock::new(None),
                leaf: d.0,
            });
            let stop = api.self_stop();
            let shared2 = Arc::clone(&shared);
            api.set_task(async move {
                stop.await;
                let (tx, rx) = tokio::sync::oneshot::channel();
                *shared2.quit_requested.try_lock().unwrap() = Some(tx);
                let _ = rx.await;
                Ok(())
            });
            Ok(shared)
        }
    }

    #[derive(ResourceDependencies)]
    struct TestSelfStopTopDependencies(Arc<TestSelfStop>);

    #[test]
    fn self_stop() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let assembly = Assembly::<TestSelfStopTopDependencies>::new_from_argv(EMPTY).unwrap();
        let tss = Arc::clone(&assembly.top.0);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();

        // Steady state: nothing.
        assert!(e.poll(&mut r).is_pending());
        assert!(tss.quit_requested.try_lock().unwrap().is_none());
        assert!(!tss.leaf.0.load(Ordering::Acquire));

        let _ = tx.try_send(()).unwrap();
        // Quit signal: received but not propagated.
        assert!(e.poll(&mut r).is_pending());
        let next_step = tss.quit_requested.try_lock().unwrap().take().unwrap();
        assert!(!tss.leaf.0.load(Ordering::Acquire));

        std::mem::drop(next_step);
        // Finally propagate
        assert!(e.poll(&mut r).is_ready());
        assert!(tss.leaf.0.load(Ordering::Acquire));
    }

    struct RunUntilSignaled(AtomicTake<tokio::sync::oneshot::Sender<()>>);

    #[resource]
    impl Resource for RunUntilSignaled {
        fn new(
            _: NoDependencies,
            _: NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            api.set_task(async move {
                let _ = rx.await;
                Ok(())
            });
            Ok(Arc::new(Self(AtomicTake::new(tx))))
        }
    }

    #[derive(ResourceDependencies)]
    struct RunUntilSignaledTop(Arc<RunUntilSignaled>);

    #[test]
    fn runs_until_resource_quits() {
        let assembly = Assembly::<RunUntilSignaledTop>::new_from_argv(EMPTY).unwrap();
        let notify = assembly.top.0.0.take().unwrap();
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = notify.send(());
        assert!(e.poll(&mut r).is_ready());
    }

    struct RunStubbornly;

    #[resource]
    impl Resource for RunStubbornly {
        fn new(
            _: NoDependencies,
            _: NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let _ = api.self_stop();
            api.set_task(std::future::pending());
            Ok(Arc::new(Self))
        }
    }

    #[derive(ResourceDependencies)]
    struct RunStubbornlyTop(#[allow(dead_code)] Arc<RunStubbornly>);

    #[test]
    fn needs_2_sigterms() {
        let assembly = Assembly::<RunStubbornlyTop>::new_from_argv(EMPTY).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        // Does not quit after the first request.
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        // Does quit after the second.
        assert!(e.poll(&mut r).is_ready());
    }

    trait TestTrait1: Send + Sync {}

    trait TestTrait2: Send + Sync {}

    #[derive(ResourceDependencies)]
    struct RequiresDynDependencies(Vec<Arc<dyn TestTrait1>>, Vec<Arc<dyn TestTrait2>>);

    struct RequiresDyn(Vec<Arc<dyn TestTrait1>>, Vec<Arc<dyn TestTrait2>>);

    #[resource]
    impl Resource for RequiresDyn {
        fn new(
            d: RequiresDynDependencies,
            _: NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self(d.0, d.1)))
        }
    }

    struct ProvidesDyn;

    impl TestTrait1 for ProvidesDyn {}

    impl TestTrait2 for ProvidesDyn {}

    #[resource]
    #[export(dyn TestTrait1)]
    #[export(dyn TestTrait2)]
    impl Resource for ProvidesDyn {
        fn new(
            _: NoDependencies,
            _: NoArgs,
            _: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            Ok(Arc::new(Self))
        }
    }

    #[derive(ResourceDependencies)]
    struct RequiresDynTop(Arc<RequiresDyn>, Arc<ProvidesDyn>);

    #[test]
    fn dyn_resource() {
        let assembly = Assembly::<RequiresDynTop>::new_from_argv(EMPTY).unwrap();
        assert_eq!(assembly.top.0.0.len(), 1);
        assert_eq!(assembly.top.0.1.len(), 1);
        let _ = Arc::clone(&assembly.top.1);
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Action {
        LogQuit,
        MainTaskStart,
        MainTaskEnd,
        Cleanup,
    }

    #[derive(Debug)]
    struct GlobalActionLog(std::sync::Mutex<Vec<Action>>);

    #[resource]
    impl Resource for GlobalActionLog {
        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            let shared = Arc::new(Self(std::sync::Mutex::new(Vec::new())));
            let shared2 = Arc::clone(&shared);
            let stopper = api.self_stop();
            api.set_task(async move {
                stopper.await;
                shared2.0.lock().unwrap().push(Action::LogQuit);
                Ok(())
            });
            Ok(shared)
        }
    }

    struct ResourceWithTaskWithCleanup;

    #[derive(ResourceDependencies)]
    struct ResourceWithTaskWithCleanupDependencies(Arc<GlobalActionLog>);

    #[derive(clap::Args)]
    #[group(skip)]
    struct ResourceWithTaskWithCleanupArgs {
        #[arg(long)]
        complete_immediately: bool,
    }

    struct TestTaskWithCleanup {
        log: Arc<GlobalActionLog>,
        complete_immediately: bool,
    }

    impl TaskWithCleanup for TestTaskWithCleanup {
        #[allow(refining_impl_trait)]
        async fn main_task(&mut self) -> Result<(), std::convert::Infallible> {
            self.log.0.lock().unwrap().push(Action::MainTaskStart);
            if !self.complete_immediately {
                std::future::pending::<()>().await;
            }
            self.log.0.lock().unwrap().push(Action::MainTaskEnd);
            Ok(())
        }

        #[allow(refining_impl_trait)]
        async fn cleanup(self) -> Result<(), std::convert::Infallible> {
            self.log.0.lock().unwrap().push(Action::Cleanup);
            Ok(())
        }
    }

    #[resource]
    impl Resource for ResourceWithTaskWithCleanup {
        fn new(
            d: ResourceWithTaskWithCleanupDependencies,
            a: ResourceWithTaskWithCleanupArgs,
            api: &mut AssemblyRuntime<'_>,
        ) -> Result<Arc<Self>, std::convert::Infallible> {
            api.set_task_with_cleanup(TestTaskWithCleanup {
                log: d.0,
                complete_immediately: a.complete_immediately,
            });
            Ok(Arc::new(Self))
        }
    }

    #[derive(ResourceDependencies)]
    struct TaskWithCleanupTop(Arc<ResourceWithTaskWithCleanup>, Arc<GlobalActionLog>);
    #[test]
    fn task_with_cleanup_long_running() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        //let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--skip-task".into()];
        let assembly = Assembly::<TaskWithCleanupTop>::new_from_argv(EMPTY).unwrap();
        let _ = assembly.top.0;
        let log = Arc::clone(&assembly.top.1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        assert_eq!(&*log.0.lock().unwrap(), &[Action::MainTaskStart]);
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
        assert_eq!(
            &*log.0.lock().unwrap(),
            &[Action::MainTaskStart, Action::Cleanup, Action::LogQuit,]
        );
    }

    #[test]
    fn task_with_cleanup_short_running() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--complete-immediately".into()];
        let assembly = Assembly::<TaskWithCleanupTop>::new_from_argv(argv).unwrap();
        let _ = assembly.top.0;
        let log = Arc::clone(&assembly.top.1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        assert_eq!(
            &*log.0.lock().unwrap(),
            &[Action::MainTaskStart, Action::MainTaskEnd,]
        );
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
        assert_eq!(
            &*log.0.lock().unwrap(),
            &[Action::MainTaskStart, Action::MainTaskEnd, Action::LogQuit,]
        );
    }
}
