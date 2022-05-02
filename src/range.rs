//!
//! Utilities for type which has range, such as module, memory page, etc.
//!

use core::cmp::Ordering;
use core::ops::Range;

pub trait RangeValue<T: Copy + PartialOrd<T> = usize>: Sized {
    fn as_range(&self) -> Range<T>;

    fn cmp(&self, val: T) -> Ordering {
        let r = self.as_range();
        if val >= r.start && val < r.end {
            Ordering::Equal
        } else if val < r.start {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    #[inline]
    fn contains(&self, v: T) -> bool {
        self.as_range().contains(&v)
    }

    fn binary_search<'a, S: AsRef<[Self]> + 'a>(s: &'a S, val: T) -> Option<&'a Self> {
        let slice = s.as_ref();
        slice
            .binary_search_by(|x| x.cmp(val))
            .ok()
            .and_then(|i| slice.get(i))
    }

    fn binary_search_mut<'a, S: AsMut<[Self]> + 'a>(s: &'a mut S, val: T) -> Option<&'a mut Self> {
        let slice = s.as_mut();
        let i = slice.binary_search_by(|x| x.cmp(val)).ok()?;
        slice.get_mut(i)
    }
}
