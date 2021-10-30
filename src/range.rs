
use std::sync::Arc;
use core::ops::Range;
use core::cmp::Ordering;

pub trait RangeValue<T: Copy + PartialOrd<T> = usize>: Sized {
    fn as_range(&self) -> Range<T>;

    fn cmp(&self, val: T) -> Ordering {
        let r = self.as_range();
        if val >= r.start && val < r.end {
            Ordering::Equal
        } else if val < r.start {
            Ordering::Greater
        } else { Ordering::Less }
    }

    #[inline]
    fn contains(&self, v: T) -> bool {
        self.as_range().contains(&v)
    }

    fn binary_search<'a, S: AsRef<[Self]>+'a>(s: &'a S, val: T) -> Option<&'a Self> {
        let slice = s.as_ref();
        slice.binary_search_by(|x| x.cmp(val)).ok().and_then(|i| slice.get(i))
    }

    fn binary_search_mut<'a, S: AsMut<[Self]>+'a>(s: &'a mut S, val: T) -> Option<&'a mut Self> {
        let slice = s.as_mut();
        let i = slice.binary_search_by(|x| x.cmp(val)).ok()?;
        slice.get_mut(i)
    }
}

impl<T: RangeValue> RangeValue for Box<T> {
    fn as_range(&self) -> Range<usize> { self.as_ref().as_range() }
}

impl<T: RangeValue> RangeValue for Arc<T> {
    fn as_range(&self) -> Range<usize> { self.as_ref().as_range() }
}