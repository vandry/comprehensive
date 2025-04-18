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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::ResourceDependencies;
use crate::assembly::sealed::ResourceBase;
use crate::assembly::{ProduceContext, RegisterContext, ResourceFut};
use crate::shutdown::{
    ShutdownSignalParticipant, ShutdownSignalParticipantCreator, TaskRunningSentinel,
};

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
    type CreationError: Into<Box<(dyn Error + 'static)>>;

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
}

/// An attribute macro that can be used to automatically supply definitions
/// for the associated types and constant of a [`Resource`].
///
/// Any definitions which are already supplied will nt be synthesised. This
/// can be useful for example for overriding `NAME`.
///
/// ```
/// # struct SomeType;
/// # type AA = comprehensive::NoDependencies;
/// # type BB = comprehensive::NoArgs;
/// # type CC = std::convert::Infallible;
/// # use std::sync::Arc;
/// use comprehensive::v1::{AssemblyRuntime, Resource, resource};
///
/// #[resource]
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
pub use comprehensive_macros::v1resource as resource;

pin_project! {
    struct TaskInner<F> {
        #[pin] fut: F,
        keepalive: TaskRunningSentinel,
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
    fn new<T>(task: T, stopper: ShutdownSignalParticipant, keepalive: TaskRunningSentinel) -> Self
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
    fn new<T>(task: T, stopper: ShutdownSignalParticipant, keepalive: TaskRunningSentinel) -> Self
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
        keepalive: TaskRunningSentinel,
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
        keepalive: TaskRunningSentinel,
        auto_stop: bool,
    ) -> ResourceFut {
        if auto_stop {
            Box::pin(AutoStopTask::new(self.0, stopper, keepalive))
        } else {
            Box::pin(SelfStopTask::new(self.0, stopper, keepalive))
        }
    }
}

mod private {
    pub struct ResourceProduction<T> {
        pub(super) shared: std::sync::Arc<T>,
        pub(super) task: Option<Box<dyn super::Task>>,
        pub(super) stopper: super::ShutdownSignalParticipant,
        pub(super) keepalive: super::TaskRunningSentinel,
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

    fn make(
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut clap::ArgMatches,
        mut stoppers: ShutdownSignalParticipantCreator,
        keepalive: TaskRunningSentinel,
    ) -> Result<Self::Production, Box<dyn Error>> {
        let deps = T::Dependencies::produce(cx)?;
        let args = T::Args::from_arg_matches(arg_matches)?;
        let mut api = AssemblyRuntime {
            stoppers: Some(&mut stoppers),
            task: None,
        };
        Ok(private::ResourceProduction {
            shared: T::new(deps, args, &mut api).map_err(Into::into)?,
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

impl<T: Resource> crate::AnyResource<{ crate::ResourceVariety::V1 as usize }> for T {
    const NAME: &str = T::NAME;
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
}
