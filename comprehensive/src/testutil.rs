use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

#[derive(Default)]
struct TestWaker(std::sync::atomic::AtomicBool);

impl std::task::Wake for TestWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

pub(crate) struct TestExecutor(std::task::Waker, Arc<TestWaker>);

impl Default for TestExecutor {
    fn default() -> Self {
        let w = Arc::new(TestWaker::default());
        Self(Arc::clone(&w).into(), w)
    }
}

impl TestExecutor {
    /// Poll the Future repeatedly until it makes no more progress.
    pub(crate) fn poll<F: Future>(&mut self, fut: &mut Pin<&mut F>) -> Poll<F::Output> {
        let mut cx = std::task::Context::from_waker(&self.0);
        loop {
            if let Poll::Ready(o) = fut.as_mut().poll(&mut cx) {
                return Poll::Ready(o);
            }
            if !self.1.0.swap(false, std::sync::atomic::Ordering::AcqRel) {
                return Poll::Pending;
            }
        }
    }
}
