use slice_dst::SliceWithHeader;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};
use try_lock::TryLock;

use crate::matrix::DepMatrix;

// One participant we can hand to the user, one for us to keep to mop up.
pub(crate) const SHUTDOWN_SIGNAL_N_PARTICIPANTS: usize = 2;

struct ShutdownSignalEntryInner {
    wakers: [TryLock<Option<Waker>>; SHUTDOWN_SIGNAL_N_PARTICIPANTS],
    unreferenced: AtomicBool,
}

pub(crate) struct ShutdownSignalEntry(Option<ShutdownSignalEntryInner>);

impl ShutdownSignalEntry {
    fn new(inert: bool, unreferenced: bool) -> Self {
        if inert {
            Self(None)
        } else {
            Self(Some(ShutdownSignalEntryInner {
                wakers: [TryLock::new(None), TryLock::new(None)],
                unreferenced: unreferenced.into(),
            }))
        }
    }
}

pub(crate) struct ShutdownSignalHeader {
    dep_matrix: OnceLock<DepMatrix>,
}

type ShutdownSignalInner = SliceWithHeader<ShutdownSignalHeader, ShutdownSignalEntry>;

#[doc(hidden)]
pub struct ShutdownSignalParticipant {
    matrix: Option<Arc<ShutdownSignalInner>>,
    row: usize,
    waker_slot: usize,
}

pub struct ShutdownSignalForwarder {
    matrix: Arc<ShutdownSignalInner>,
    row: usize,
}

#[doc(hidden)]
pub struct ShutdownSignalParticipantCreator(Option<ShutdownSignalParticipant>, bool);

impl Iterator for ShutdownSignalParticipantCreator {
    type Item = ShutdownSignalParticipant;

    fn next(&mut self) -> Option<ShutdownSignalParticipant> {
        let (current, following) = match self.0.take() {
            None => (None, None),
            Some(p) => {
                let following = if p.waker_slot == SHUTDOWN_SIGNAL_N_PARTICIPANTS - 1 {
                    None
                } else {
                    Some(ShutdownSignalParticipant {
                        matrix: p.matrix.as_ref().map(Arc::clone),
                        row: p.row,
                        waker_slot: p.waker_slot + 1,
                    })
                };
                (Some(p), following)
            }
        };
        self.0 = following;
        current
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.1 {
            (0, Some(0))
        } else {
            (
                SHUTDOWN_SIGNAL_N_PARTICIPANTS,
                Some(SHUTDOWN_SIGNAL_N_PARTICIPANTS),
            )
        }
    }
}

impl ShutdownSignalParticipantCreator {
    // Like .take(1).next() but more efficient
    pub(crate) fn into_inner(self) -> Option<ShutdownSignalParticipant> {
        self.0
    }
}

impl ExactSizeIterator for ShutdownSignalParticipantCreator {}

enum AddOneState<I> {
    Inner(I),
    Done,
}

struct AddOne<I> {
    size_min: usize,
    size_max: Option<usize>,
    state: AddOneState<I>,
}

impl<I: Iterator> AddOne<I> {
    fn new(it: I) -> Self {
        let (size_min, size_max) = it.size_hint();
        Self {
            size_min: size_min.checked_add(1).expect("usize::MAX too many nodes"),
            size_max: size_max.map(|v| v.checked_add(1).expect("usize::MAX too many nodes")),
            state: AddOneState::Inner(it),
        }
    }
}

impl<I> Iterator for AddOne<I>
where
    I: Iterator,
    I::Item: Default,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            AddOneState::Inner(ref mut it) => match it.next() {
                Some(v) => Some(v),
                None => {
                    self.state = AddOneState::Done;
                    Some(Self::Item::default())
                }
            },
            AddOneState::Done => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size_min, self.size_max)
    }
}

impl<I> ExactSizeIterator for AddOne<I>
where
    I: ExactSizeIterator,
    <I as Iterator>::Item: Default,
{
}

pub(crate) struct ShutdownSignal<'a>(Arc<ShutdownSignalInner>, usize, &'a DepMatrix);

impl<'a> ShutdownSignal<'a> {
    pub(crate) fn new<I>(it: I, dep_matrix: &'a DepMatrix) -> Self
    where
        I: std::iter::ExactSizeIterator<Item = bool>,
    {
        Self(
            SliceWithHeader::new(
                ShutdownSignalHeader {
                    dep_matrix: OnceLock::new(),
                },
                AddOne::new(it).enumerate().map(|(i, inert)| {
                    ShutdownSignalEntry::new(inert, dep_matrix.is_row_unreferenced(i))
                }),
            ),
            0,
            dep_matrix,
        )
    }
}

impl Iterator for ShutdownSignal<'_> {
    type Item = Option<ShutdownSignalParticipantCreator>;

    fn next(&mut self) -> Option<Self::Item> {
        let i = self.1;
        if i < self.0.slice.len() {
            self.1 += 1;
            // .is_present() wrongly returns false in the case of an empty assembly,
            // so special-case that.
            if self.2.is_row_live(i) || self.0.slice.len() == 1 {
                Some(Some(if self.0.slice[i].0.is_some() {
                    ShutdownSignalParticipantCreator(
                        Some(ShutdownSignalParticipant {
                            matrix: Some(Arc::clone(&self.0)),
                            row: i,
                            waker_slot: 0,
                        }),
                        false,
                    )
                } else {
                    ShutdownSignalParticipantCreator(None, true)
                }))
            } else {
                Some(None)
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.0.slice.len();
        (l, Some(l))
    }
}

impl ExactSizeIterator for ShutdownSignal<'_> {}

fn wake_or_pass_through(ss: &ShutdownSignalInner, i: usize) -> bool {
    if let Some(ref inner) = ss.slice[i].0 {
        inner.unreferenced.store(true, Ordering::Release);
        for slot in &inner.wakers {
            if let Some(mut maybe_waker) = slot.try_lock() {
                if let Some(waker) = maybe_waker.take() {
                    waker.wake()
                }
            }
        }
        false
    } else {
        // This row is inert, nobody is listening.
        // Propagate on its behalf.
        true
    }
}

fn propagate(ss: &ShutdownSignalInner, dep_matrix: &DepMatrix, row: usize) {
    // On entry, our own refcount is either 0 or 1 (we don't create
    // ShutdownSignalForwarder unless that's true and don't call ourselves
    // recursively unless that's true) and 0 means we have already been called,
    // so we only proceed if it was 1. Either way it will become 0.
    for i in dep_matrix
        .decref_last_propagate(row)
        .filter(|i| wake_or_pass_through(ss, *i))
    {
        propagate(ss, dep_matrix, i);
    }
}

fn propagate_mut(ss: &ShutdownSignalInner, dep_matrix: &mut DepMatrix, row: usize) {
    for i in dep_matrix.completely_unref(row) {
        if dep_matrix.decref(i) && wake_or_pass_through(ss, i) {
            propagate_mut(ss, dep_matrix, i);
        }
    }
}

impl ShutdownSignalForwarder {
    pub(crate) fn propagate(self) {
        propagate(
            &self.matrix,
            self.matrix.header.dep_matrix.get().unwrap(),
            self.row,
        )
    }

    pub(crate) fn accept_dep_matrix(&self, dep_matrix: DepMatrix) {
        self.matrix
            .header
            .dep_matrix
            .get_or_init(move || dep_matrix);
    }

    pub(crate) fn completely_unref(&self, i: usize, dep_matrix: &mut DepMatrix) {
        self.matrix.slice[i]
            .0
            .as_ref()
            .unwrap()
            .unreferenced
            .store(true, Ordering::Release);
        propagate_mut(&self.matrix, dep_matrix, i);
    }

    #[cfg(test)]
    pub(crate) fn edges(&self) -> impl Iterator<Item = (usize, usize)> {
        self.matrix.header.dep_matrix.get().unwrap().edges()
    }
}

impl Drop for ShutdownSignalParticipant {
    fn drop(&mut self) {
        if let Some(ref mut matrix) = self.matrix {
            if let Some(mut maybe_waker) =
                matrix.slice[self.row].0.as_ref().unwrap().wakers[self.waker_slot].try_lock()
            {
                let _ = maybe_waker.take();
            }
        }
    }
}

impl ShutdownSignalParticipant {
    fn future_ready(&mut self) -> Poll<ShutdownSignalForwarder> {
        let matrix = self.matrix.take().unwrap();
        if let Some(mut maybe_waker) =
            matrix.slice[self.row].0.as_ref().unwrap().wakers[self.waker_slot].try_lock()
        {
            let _ = maybe_waker.take();
        }
        Poll::Ready(ShutdownSignalForwarder {
            matrix,
            row: self.row,
        })
    }
}

impl Future for ShutdownSignalParticipant {
    type Output = ShutdownSignalForwarder;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<ShutdownSignalForwarder> {
        let this = Pin::into_inner(self);
        let matrix = this.matrix.as_mut().expect("poll called after Ready");
        let entry = &matrix.slice[this.row].0.as_ref().unwrap();
        if entry.unreferenced.load(Ordering::Acquire) {
            return this.future_ready();
        }
        let took_lock = entry.wakers[this.waker_slot]
            .try_lock()
            .map(|mut maybe_waker| {
                let park = maybe_waker
                    .as_ref()
                    .map(|w| !w.will_wake(cx.waker()))
                    .unwrap_or(true);
                if park {
                    maybe_waker.replace(cx.waker().clone())
                } else {
                    None
                }
            });
        if let Some(old) = took_lock {
            if let Some(waker) = old {
                waker.wake();
            }
            if entry.unreferenced.load(Ordering::Acquire) {
                return this.future_ready();
            }
        }
        Poll::Pending
    }
}

impl futures::future::FusedFuture for ShutdownSignalParticipant {
    fn is_terminated(&self) -> bool {
        self.matrix
            .as_ref()
            .map(|m| {
                m.slice[self.row]
                    .0
                    .as_ref()
                    .unwrap()
                    .unreferenced
                    .load(Ordering::Acquire)
            })
            .unwrap_or(true)
    }
}
