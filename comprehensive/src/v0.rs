//! Original (version 0) [`Resource`] for Comprehensive.
//!
//! This type of resource will be deprecated in favour of
//! `v1::Resource` soon. It has flaws:
//!
//! ## Abrupt shutdown for resources with no cleanup
//!
//! Many resources have no particular actions to take at shutdown time. These
//! can implement the simpler [`Resource::run`] instead of
//! [`Resource::run_with_termination_signal`]. But that does not do the right
//! thing in most cases. It causes the resource task to immediately stop
//! running upon receiving a shutdown signal. The desired behaviour is almost
//! always instead to keep running until at least all other resources that
//! depend on this one quit, then stop running together with the assembly.
//! The latter cannot reasonably be implemented with this version.
//!
//! v1 will bring a richer shutdown API that separates the notification of
//! shutdown intent from the release of shutdown readiness.
//!
//! ## Awkward ownership
//!
//! Experience has shown that [`Resource::run`] almost always needs owned, or
//! at least mutable access to some state. But in this version the only
//! resource state we have is an [`Arc`] of the resource that is used both for
//! exposing the resource to its reverse dependencies and for
//! [`Resource::run`], leading to the latter almost always needing an interior
//! mutability hack of one kind or another in [`Resource::run`] to gain
//! mutable or owned access to some part of the state that the other holders
//! of the [`Arc`] shouldn't really even see at all.
//!
//! v1 will bring a new `ResourceTask` object with its own state that is
//! distinct from the [`Arc`] that is shared around to reverse dependencies.

use clap::{Args, FromArgMatches};
use futures::{FutureExt, ready};
use pin_project_lite::pin_project;
use std::error::Error;
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{Notify, futures::Notified};
use tracing::instrument::Instrument as _;
use tracing::{Level, error, info, span};

use crate::ResourceDependencies;
use crate::assembly::sealed::ResourceBase;
use crate::assembly::{ProduceContext, RegisterContext};
use crate::dependencies::sealed::AvailableResource;
use crate::drop_stream::Sentinel;
use crate::shutdown::{ShutdownSignalParticipant, ShutdownSignalParticipantCreator};

/// Passed to resources to offer resources a chance to react to a termination
/// request signal. Interested resources should call [`ShutdownNotify::subscribe`].
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

/// The main unit of work in an [`crate::Assembly`] and the trait common to
/// each of the nodes in its DAG.
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

    /// The name of this resource. Used in logs and resource graph
    /// diagnostics.
    const NAME: &str;

    /// Construct a resource of this type. Called while the graph of all
    /// resources is built in [`crate::Assembly::new`].
    fn new(deps: Self::Dependencies, args: Self::Args) -> Result<Self, Box<dyn Error>>;

    /// Execute a background task belonging to this resource. Awaited
    /// together with the tasks for all other resourcees in
    /// [`crate::Assembly::run`].
    ///
    /// The default implementation exits immediately.
    fn run(&self) -> impl Future<Output = Result<(), Box<dyn Error>>> + Send {
        async { Ok(()) }
    }

    /// Execute a background task belonging to this resource. Awaited
    /// together with the tasks for all other resourcees in
    /// [`crate::Assembly::run`].
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

pin_project! {
    struct NotifyForward {
        notify: Arc<Notify>,
        #[pin] sub: ShutdownSignalParticipant,
    }
}

pin_project! {
    struct NotifyInner<F> {
        #[pin] fut: F,
        task_running: Sentinel,
    }
}

pin_project! {
    struct NotifyHelper<F> {
        #[pin] forward: Option<NotifyForward>,
        #[pin] inner: Option<NotifyInner<F>>,
    }
}

impl<F> NotifyHelper<F> {
    fn new(
        fut: F,
        notify: Arc<Notify>,
        sub: ShutdownSignalParticipant,
        task_running: Sentinel,
    ) -> Self {
        Self {
            forward: Some(NotifyForward { notify, sub }),
            inner: Some(NotifyInner { fut, task_running }),
        }
    }
}

impl<F, U> Future for NotifyHelper<F>
where
    F: Future<Output = Result<(), U>>,
    U: std::fmt::Display,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let done = if let Some(forward) = this.forward.as_mut().as_pin_mut() {
            forward.project().sub.poll(cx)
        } else {
            Poll::Pending
        };
        if let Poll::Ready(forwarder) = done {
            if let Some(forward) = this.forward.take() {
                forward.notify.notify_waiters();
            }
            forwarder.propagate();
        }
        if let Some(inner) = this.inner.as_mut().as_pin_mut() {
            let inner = inner.project();
            let r = ready!(inner.fut.poll(cx));
            this.inner.set(None);
            match r {
                Err(e) => {
                    error!("failed: {}", e);
                    return Poll::Ready(Err(e));
                }
                Ok(_) => {
                    info!("exited successfully");
                }
            }
        }
        if this.forward.is_none() && this.inner.is_none() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T: Resource> ResourceBase<{ crate::ResourceVariety::V0 as usize }> for T {
    const NAME: &str = T::NAME;
    type Production = (Arc<T>, ShutdownSignalParticipant, Sentinel);

    fn register_recursive(cx: &mut RegisterContext<'_>) {
        T::Dependencies::register(cx);
    }

    fn augment_args(c: clap::Command) -> clap::Command {
        T::Args::augment_args(c)
    }

    fn make(
        cx: &mut ProduceContext<'_>,
        arg_matches: &mut clap::ArgMatches,
        stoppers: ShutdownSignalParticipantCreator,
        task_running: Sentinel,
        _: crate::assembly::sealed::DependencyTest,
    ) -> Result<Self::Production, Box<dyn Error>> {
        let deps = T::Dependencies::produce(cx)?;
        let args = T::Args::from_arg_matches(arg_matches)?;
        let shared = Arc::new(T::new(deps, args)?);
        Ok((shared, stoppers.into_inner().unwrap(), task_running))
    }

    fn shared(re: &Self::Production) -> Arc<T> {
        Arc::clone(&re.0)
    }

    fn task(
        (user_task, shutdown_participant, task_running): Self::Production,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error>>> + Send>> {
        let notify = Arc::new(Notify::new());
        let notify2 = Arc::clone(&notify);
        let span = span!(Level::INFO, "Comprehensive", resource = T::NAME);
        Box::pin(
            NotifyHelper::new(
                async move {
                    let shutdown_notify = ShutdownNotify::new(&notify2);
                    user_task
                        .run_with_termination_signal(&shutdown_notify)
                        .await
                },
                notify,
                shutdown_participant,
                task_running,
            )
            .instrument(span),
        )
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

    use futures::poll;
    use tokio::sync::Notify;

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
            Ok(Self {})
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            std::future::pending().await
        }
    }

    #[derive(Debug)]
    struct Leaf2 {
        fail: bool,
    }

    #[derive(clap::Args)]
    #[group(skip)]
    struct Leaf2Args {
        #[arg(long)]
        fail: bool,
    }

    impl Resource for Leaf2 {
        type Args = Leaf2Args;
        type Dependencies = NoDependencies;
        const NAME: &str = "Leaf2";

        fn new(_: NoDependencies, a: Leaf2Args) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self { fail: a.fail })
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            if self.fail {
                Err(Box::new(NoGood))
            } else {
                std::future::pending().await
            }
        }
    }

    #[allow(dead_code)]
    #[derive(ResourceDependencies)]
    struct MidDependencies(#[old_style] Arc<Leaf1>, #[old_style] Arc<Leaf2>);

    struct Mid;

    impl Resource for Mid {
        type Args = NoArgs;
        type Dependencies = MidDependencies;
        const NAME: &str = "Mid";

        fn new(_: MidDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }

        async fn run(&self) -> Result<(), Box<dyn Error>> {
            std::future::pending().await
        }
    }

    #[derive(ResourceDependencies)]
    struct TopDependencies {
        #[old_style]
        _mid: Arc<Mid>,
        #[old_style]
        _l2: Arc<Leaf2>,
    }

    const EMPTY: &[std::ffi::OsString] = &[];

    #[test]
    fn fail_assembly() {
        let argv: Vec<std::ffi::OsString> = vec!["cmd".into(), "--fail".into()];
        let mut e = TestExecutor::default();
        let mut r = pin!(
            Assembly::<TopDependencies>::new_from_argv(argv)
                .unwrap()
                .run_with_termination_signal(futures::stream::pending())
        );
        let Poll::Ready(Err(e)) = e.poll(&mut r) else {
            panic!("poll should have returned an error");
        };
        assert_eq!(e.to_string(), "no good");
    }

    #[test]
    fn succeed_assembly() {
        let mut e = TestExecutor::default();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            Assembly::<TopDependencies>::new_from_argv(EMPTY)
                .unwrap()
                .run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        match e.poll(&mut r) {
            Poll::Ready(Ok(())) => (),
            other => {
                panic!("want Poll::Ready(Ok(())) got {:?}", other);
            }
        }
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
    struct RunUntilSignaledTop(#[old_style] Arc<RunUntilSignaled>);

    #[test]
    fn runs_until_resource_quits() {
        let assembly = Assembly::<RunUntilSignaledTop>::new_from_argv(EMPTY).unwrap();
        let notify = &Arc::clone(&assembly.top.0).0;
        let mut r = pin!(assembly.run_with_termination_signal(futures::stream::pending()));
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        notify.notify_waiters();
        assert!(e.poll(&mut r).is_ready());
    }

    #[test]
    fn runs_until_overall_shutdown() {
        let assembly = Assembly::<RunUntilSignaledTop>::new().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
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
    struct RunStubbornlyTop(#[old_style] Arc<RunStubbornly>);

    #[tokio::test]
    async fn needs_2_sigterms() {
        let assembly = Assembly::<RunStubbornlyTop>::new().unwrap();
        let _ = assembly.top.0;
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

    struct DoesNothing;

    impl Resource for DoesNothing {
        type Args = NoArgs;
        type Dependencies = RunUntilSignaledTop;
        const NAME: &str = "RunStubbornly";

        fn new(_: RunUntilSignaledTop, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    #[derive(ResourceDependencies)]
    struct PropagatesShutdownTop(#[old_style] Arc<DoesNothing>);

    #[test]
    fn idle_resource_propagates_shutdown() {
        let assembly = Assembly::<PropagatesShutdownTop>::new_from_argv(EMPTY).unwrap();
        let _ = assembly.top.0;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut r = pin!(
            assembly.run_with_termination_signal(tokio_stream::wrappers::ReceiverStream::new(rx))
        );
        let mut e = TestExecutor::default();
        assert!(e.poll(&mut r).is_pending());
        let _ = tx.try_send(()).unwrap();
        assert!(e.poll(&mut r).is_ready());
    }
}
