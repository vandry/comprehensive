//! Health tracking and reporting support for [`comprehensive`].
//!
//! This module exposes a single [`Resource`] type which acts as the
//! interface between resources that wish to publish health status
//! and other resources that wish to consume it.
//!
//! The health result tracked by [`HealthReporter`] is defined as a
//! boolean status representing the server's willingness (or readiness)
//! to accept incoming requests. it is true iff all of the published
//! contributing signals are healthy (or, trivially, if none are
//! registered) and false otherwise.
//!
//! # Publishing a health signal
//!
//! ```
//! use comprehensive::{NoArgs, ResourceDependencies, Resource};
//! use comprehensive::health::{HealthReporter, HealthSignaller};
//!
//! #[derive(ResourceDependencies)]
//! struct PeriodicallyBrokenDependencies(std::sync::Arc<HealthReporter>);
//!
//! struct PeriodicallyBroken {
//!     signaller: HealthSignaller,
//! }
//!
//! impl Resource for PeriodicallyBroken {
//!     type Args = comprehensive::NoArgs;
//!     type Dependencies = PeriodicallyBrokenDependencies;
//!     const NAME: &str = "indecisive health";
//!
//!     fn new(d: PeriodicallyBrokenDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
//!         Ok(Self {
//!             signaller: d.0.register(Self::NAME)?,
//!         })
//!     }
//!
//!     async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
//!         // Oscillate between healthy and unhealthy every 2 seconds.
//!         loop {
//!             tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
//!             self.signaller.set_healthy(true);
//!             tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
//!             self.signaller.set_healthy(false);
//!         }
//!     }
//! }
//! ```
//!
//! # Consuming the aggregated health signal
//!
//! There are 2 methods, pull and push. See
//! [`HealthReporter::is_healthy`] and [`HealthReporter::subscribe`]
//! as well as the reference implementations of consumers for
//! [gRPC](https://github.com/vandry/comprehensive/blob/master/comprehensive_grpc/src/lib.rs)
//! and
//! [HTTP](https://github.com/vandry/comprehensive/blob/master/src/http.rs).

use futures::future::Either;
use futures::pin_mut;
use lazy_static::lazy_static;
use prometheus::register_gauge_vec;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;

use crate::{NoArgs, NoDependencies, Resource};

lazy_static! {
    static ref HEALTH_SIGNALS: prometheus::GaugeVec = register_gauge_vec!(
        "comprehensive_health_signal",
        "Assembly health signal (boolean)",
        &["signal"]
    )
    .unwrap();
}

/// An object returned by [`HealthReporter::register`] that allows a
/// health signal to publish its status.
pub struct HealthSignaller {
    reporter: Arc<HealthReporter>,
    index: usize,
}

impl HealthSignaller {
    /// Set the new current health status for this signal.
    pub fn set_healthy(&self, healthy: bool) {
        let reporter = &self.reporter;
        let signal = &reporter.signals[self.index];
        let mut lock = signal.healthy.lock().unwrap();
        if healthy != *lock {
            *lock = healthy;
            if healthy {
                reporter.unhealthy_count.fetch_sub(1, Ordering::Release);
            } else {
                reporter.unhealthy_count.fetch_add(1, Ordering::Release);
            }
            reporter.maybe_notify();
            HEALTH_SIGNALS
                .with_label_values(&[signal.name])
                .set(if healthy { 1.0 } else { 0.0 });
        }
    }
}

struct Signal {
    name: &'static str,
    healthy: std::sync::Mutex<bool>,
}

/// A [`Resource`] that receives health status from publishers, aggregates
/// them into a single boolean, and publishes the result to interested
/// resources.
///
/// 2 components of [`comprehensive`] that currently consume and externalise
/// the aggregated health signal are [`comprehensive::http::HttpServer`] and
/// [`comprehensive_grpc::GrpcServer`](https://docs.rs/comprehensive_grpc/latest/comprehensive_grpc/struct.GrpcServer.html).
pub struct HealthReporter {
    signals: boxcar::Vec<Signal>,
    unhealthy_count: AtomicU32,
    watch: watch::Sender<bool>,
}

impl HealthReporter {
    /// Get the current overall health status (pull mode).
    pub fn is_healthy(&self) -> bool {
        self.unhealthy_count.load(Ordering::Acquire) == 0
    }

    /// Get a channel that will deliver the current and future
    /// overall health statuses (push mode).
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.watch.subscribe()
    }

    fn maybe_notify(&self) {
        self.watch.send_if_modified(|value| {
            let healthy = self.is_healthy();
            if *value == healthy {
                false
            } else {
                *value = healthy;
                true
            }
        });
    }

    /// Register a new health signal.
    ///
    /// Returns a new [`HealthSignaller`] specific to this new signal which
    /// can later be used to set the status of the signal. The initial
    /// status of each signal is unhealthy (false), which means that the
    /// overall health status also becomes unhealthy upon calling this
    /// (if it wasn't already).
    ///
    /// This should be called at initialisation time (from [`Resource::new`]),
    /// not at runtime (from [`Resource::run`]).
    pub fn register(
        self: &Arc<Self>,
        name: &'static str,
    ) -> Result<HealthSignaller, crate::ComprehensiveError> {
        let index = self.signals.push(Signal {
            name,
            healthy: std::sync::Mutex::new(false),
        });
        if self.unhealthy_count.fetch_add(1, Ordering::AcqRel) == 0 {
            self.maybe_notify();
            HEALTH_SIGNALS.with_label_values(&[name]).set(0.0);
        }
        Ok(HealthSignaller {
            reporter: Arc::clone(self),
            index,
        })
    }

    fn unhealthy_list(&self) -> (String, usize) {
        let mut v = self
            .signals
            .iter()
            .filter_map(|(_, s)| match *s.healthy.lock().unwrap() {
                true => None,
                false => Some(s.name),
            })
            .collect::<Vec<_>>();
        v.sort();
        (v.join(", "), v.len())
    }

    async fn startup_health_notices(&self, rx: &mut watch::Receiver<bool>) {
        // At startup: announce every 30 seconds what is not yet healthy.
        const STARTUP_ANNOUNCE_INTERVAL: Duration = Duration::from_millis(30000);
        let start = Instant::now();
        loop {
            let deadline = tokio::time::Instant::now() + STARTUP_ANNOUNCE_INTERVAL;
            loop {
                if *rx.borrow_and_update() {
                    log::info!(
                        "After {}s, monitoring {} signals, all healthy",
                        std::time::Instant::now()
                            .duration_since(start)
                            .as_secs_f64(),
                        self.signals.count()
                    );
                    return;
                }
                let sleeper = tokio::time::sleep_until(deadline);
                let changed = rx.changed();
                pin_mut!(sleeper);
                pin_mut!(changed);
                if let Either::Left(_) = futures::future::select(sleeper, changed).await {
                    break;
                }
            }
            let (list, count) = self.unhealthy_list();
            log::warn!(
                "After {}s, {} signals are still unhealthy: {}",
                std::time::Instant::now()
                    .duration_since(start)
                    .as_secs_f64(),
                count,
                list
            );
        }
    }

    async fn wait_until_unhealthy(&self, rx: &mut watch::Receiver<bool>) {
        while *rx.borrow_and_update() {
            let _ = rx.changed().await;
        }
    }

    async fn complain_until_healthy(&self, rx: &mut watch::Receiver<bool>) {
        let mut last_count = 0;
        let mut last_list = String::from("");
        while !*rx.borrow_and_update() {
            let (list, count) = self.unhealthy_list();
            if count != last_count || list != last_list {
                log::warn!("{} unhealthy signal: {}", count, list);
                last_count = count;
                last_list = list;
            }
            let _ = rx.changed().await;
        }
        log::info!("All {} signals are healthy again", self.signals.count());
    }
}

impl Resource for HealthReporter {
    type Args = NoArgs;
    type Dependencies = NoDependencies;
    const NAME: &str = "Health reporter";

    fn new(_: NoDependencies, _: NoArgs) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            signals: boxcar::Vec::new(),
            watch: watch::Sender::new(true),
            unhealthy_count: AtomicU32::new(0),
        })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.signals.is_empty() {
            log::info!("No health signals registered. Server is trivially always healthy.");
            return Ok(());
        }
        let mut rx = self.watch.subscribe();
        self.startup_health_notices(&mut rx).await;
        loop {
            self.wait_until_unhealthy(&mut rx).await;
            self.complain_until_healthy(&mut rx).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::poll;
    use std::pin::pin;

    #[derive(crate::ResourceDependencies)]
    struct TestAssembly(Arc<HealthReporter>);

    #[tokio::test]
    async fn no_signals_is_healthy() {
        let argv = vec!["cmd"];
        let assembly = crate::Assembly::<TestAssembly>::new_from_argv(argv).unwrap();

        assert!(assembly.top.0.is_healthy());
        let mut rx = assembly.top.0.subscribe();
        assert_eq!(*rx.borrow_and_update(), true);
        assert!(poll!(pin!(rx.changed())).is_pending());
    }

    #[tokio::test]
    async fn one_signal_is_unhealthy() {
        let argv = vec!["cmd"];
        let assembly = crate::Assembly::<TestAssembly>::new_from_argv(argv).unwrap();

        let _ = assembly.top.0.register("nobody");

        assert!(!assembly.top.0.is_healthy());
        let mut rx = assembly.top.0.subscribe();
        assert_eq!(*rx.borrow_and_update(), false);
        assert!(poll!(pin!(rx.changed())).is_pending());
    }

    #[tokio::test]
    async fn one_signal_is_healthy() {
        let argv = vec!["cmd"];
        let assembly = crate::Assembly::<TestAssembly>::new_from_argv(argv).unwrap();

        assembly.top.0.register("nobody").unwrap().set_healthy(true);

        assert!(assembly.top.0.is_healthy());
        let mut rx = assembly.top.0.subscribe();
        assert_eq!(*rx.borrow_and_update(), true);
        assert!(poll!(pin!(rx.changed())).is_pending());
    }

    #[tokio::test]
    async fn one_of_two_is_unhealthy() {
        let argv = vec!["cmd"];
        let assembly = crate::Assembly::<TestAssembly>::new_from_argv(argv).unwrap();

        let _ = assembly.top.0.register("sad");
        assembly.top.0.register("happy").unwrap().set_healthy(true);

        assert!(!assembly.top.0.is_healthy());
        let mut rx = assembly.top.0.subscribe();
        assert_eq!(*rx.borrow_and_update(), false);
        assert!(poll!(pin!(rx.changed())).is_pending());
    }

    #[tokio::test]
    async fn changes() {
        let argv = vec!["cmd"];
        let assembly = crate::Assembly::<TestAssembly>::new_from_argv(argv).unwrap();

        let signal = assembly.top.0.register("variable").unwrap();

        assert!(!assembly.top.0.is_healthy());
        let mut rx = assembly.top.0.subscribe();
        assert!(poll!(pin!(rx.changed())).is_pending());

        signal.set_healthy(true);

        assert!(assembly.top.0.is_healthy());
        assert!(poll!(pin!(rx.changed())).is_ready());
        assert_eq!(*rx.borrow_and_update(), true);
        assert!(poll!(pin!(rx.changed())).is_pending());

        signal.set_healthy(false);

        assert!(!assembly.top.0.is_healthy());
        assert!(poll!(pin!(rx.changed())).is_ready());
        assert_eq!(*rx.borrow_and_update(), false);
        assert!(poll!(pin!(rx.changed())).is_pending());
    }
}
