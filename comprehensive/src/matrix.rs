use either::Either;
use fixedbitset::FixedBitSet;
use slice_dst::SliceWithHeader;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct MatrixRow {
    refcount: AtomicUsize,
    children: FixedBitSet,
}

impl MatrixRow {
    fn new(columns: usize) -> Self {
        Self {
            refcount: AtomicUsize::new(1),
            children: FixedBitSet::with_capacity(columns),
        }
    }

    fn is_present(&self) -> bool {
        !self.children.is_empty()
    }
}

#[derive(Debug)]
struct Header {
    n_live_rows: usize,
}

type DepMatrixInner = SliceWithHeader<Header, MatrixRow>;

#[derive(Debug)]
pub(crate) struct DepMatrix(Box<DepMatrixInner>);

impl DepMatrix {
    pub(crate) fn new(rows: usize, columns: usize) -> Self {
        Self(SliceWithHeader::new(
            Header { n_live_rows: rows },
            std::iter::repeat_n((), rows).map(|_| MatrixRow::new(columns)),
        ))
    }

    pub(crate) fn get_bit(&self, row: usize, column: usize) -> bool {
        self.0.slice[row].children.contains(column)
    }

    pub(crate) fn decref_last_propagate(&self, row: usize) -> impl Iterator<Item = usize> {
        if self.0.slice[row].refcount.fetch_min(0, Ordering::Release) == 1 {
            Either::Left(self.0.slice[row].children.ones().filter(|i| {
                // If the child's refcount has become 1 we should propagate to it.
                // Going below 1 will happen when it calls its own .decref_last_propagate().
                self.0.slice[*i].refcount.fetch_sub(1, Ordering::Release) == 2
            }))
        } else {
            Either::Right(std::iter::empty())
        }
    }

    pub(crate) fn completely_unref(&mut self, row: usize) -> impl Iterator<Item = usize> + use<> {
        if std::mem::take(self.0.slice[row].refcount.get_mut()) != 0 {
            Either::Left(std::mem::take(&mut self.0.slice[row].children).into_ones())
        } else {
            Either::Right(std::iter::empty())
        }
    }

    pub(crate) fn decref(&mut self, row: usize) -> bool {
        let refcount = self.0.slice[row].refcount.get_mut();
        *refcount -= 1;
        *refcount == 1
    }

    pub(crate) fn is_row_live(&self, row: usize) -> bool {
        self.0.slice[row].is_present()
    }

    pub(crate) fn is_row_unreferenced(&self, row: usize) -> bool {
        self.0.slice[row].refcount.load(Ordering::Acquire) < 2
    }

    pub(crate) fn edges(&self) -> impl Iterator<Item = (usize, usize)> {
        self.0.slice.iter().enumerate().flat_map(|(row, e)| {
            e.children
                .ones()
                .filter(|column| self.0.slice[*column].is_present())
                .map(move |column| (row, column))
        })
    }

    pub(crate) fn n_live_rows(&self) -> usize {
        self.0.header.n_live_rows
    }

    pub(crate) fn set_bit(&mut self, row: usize, column: usize) {
        self.0.slice[row].children.insert(column);
        *self.0.slice[column].refcount.get_mut() += 1
    }

    pub(crate) fn with_incref(&mut self, row: usize, f: impl FnOnce(&mut Self)) {
        *self.0.slice[row].refcount.get_mut() += 1;
        f(self);
        *self.0.slice[row].refcount.get_mut() -= 1;
    }

    pub(crate) fn remove_unreferenced(&mut self) {
        let l = self.0.slice.len();
        let mut any_removed = false;
        for i in 0..l {
            if *self.0.slice[i].refcount.get_mut() == 1 {
                self.unreference(i);
                any_removed = true;
            }
        }
        if any_removed {
            self.0.header.n_live_rows = self.0.slice.iter().filter(|e| e.is_present()).count();
        }
    }

    fn unreference(&mut self, i: usize) {
        let e = &mut self.0.slice[i];
        let refcount = e.refcount.get_mut();
        *refcount -= 1;
        if *refcount == 0 {
            for j in std::mem::take(&mut e.children).into_ones() {
                self.unreference(j);
            }
        }
    }

    pub fn count_row(&self, row: usize) -> usize {
        self.0.slice[row].children.count_ones(..)
    }

    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = usize> {
        self.0.slice[row].children.ones()
    }
}
