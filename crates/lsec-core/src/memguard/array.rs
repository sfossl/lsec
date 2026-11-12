use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::MemguardError;

pub struct ProtectedArray<const N: usize>([u8; N]);

impl<const N: usize> ProtectedArray<N> {
    #[inline]
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    #[inline]
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, MemguardError> {
        if slice.len() != N {
            return Err(MemguardError::LengthMismatch {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    #[inline]
    pub fn with_exposed<R>(&self, f: impl FnOnce(&[u8; N]) -> R) -> R {
        f(&self.0)
    }

    #[inline]
    pub fn with_exposed_mut<R>(&mut self, f: impl FnOnce(&mut [u8; N]) -> R) -> R {
        f(&mut self.0)
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    #[inline]
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Zeroize for ProtectedArray<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> ZeroizeOnDrop for ProtectedArray<N> {}

impl<const N: usize> Drop for ProtectedArray<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> Deref for ProtectedArray<N> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ProtectedArray<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for ProtectedArray<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for ProtectedArray<N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for ProtectedArray<N> {
    #[inline]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> TryFrom<&[u8]> for ProtectedArray<N> {
    type Error = MemguardError;

    #[inline]
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl<const N: usize> ConstantTimeEq for ProtectedArray<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for ProtectedArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for ProtectedArray<N> {}

impl<const N: usize> fmt::Debug for ProtectedArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedArray<{}>(**REDACTED**)", N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_array_creation_and_deref() {
        let arr = ProtectedArray::<4>::new([1, 2, 3, 4]);
        assert_eq!(arr.len(), 4);
        assert!(!arr.is_empty());
        assert_eq!(&arr[..], &[1, 2, 3, 4]);
        assert_eq!(arr.as_array(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_array_zeroed() {
        let arr = ProtectedArray::<8>::zeroed();
        assert_eq!(&arr[..], &[0u8; 8]);
    }

    #[test]
    fn test_array_from_slice() {
        let valid = [42u8; 32];
        let arr = ProtectedArray::<32>::from_slice(&valid).unwrap();
        assert_eq!(&arr[..], &valid);

        let invalid = [42u8; 16];
        let err = ProtectedArray::<32>::from_slice(&invalid).unwrap_err();
        match err {
            MemguardError::LengthMismatch { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("expected length mismatch error"),
        }
    }

    #[test]
    fn test_try_from_slice() {
        let data = [7u8; 16];
        let arr: ProtectedArray<16> = (&data[..]).try_into().unwrap();
        assert_eq!(&arr[..], &data);
    }

    #[test]
    fn test_with_exposed() {
        let arr = ProtectedArray::<4>::new([10, 20, 30, 40]);
        let sum = arr.with_exposed(|slice| slice.iter().sum::<u8>());
        assert_eq!(sum, 100);
    }

    #[test]
    fn test_with_exposed_mut() {
        let mut arr = ProtectedArray::<4>::zeroed();
        arr.with_exposed_mut(|slice| {
            slice[0] = 99;
        });
        assert_eq!(arr[0], 99);
    }

    #[test]
    fn test_constant_time_equality() {
        let a = ProtectedArray::<4>::new([1, 2, 3, 4]);
        let b = ProtectedArray::<4>::new([1, 2, 3, 4]);
        let c = ProtectedArray::<4>::new([1, 2, 3, 5]);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn test_debug_redacted() {
        let arr = ProtectedArray::<16>::new([0xff; 16]);
        let debug_str = format!("{:?}", arr);
        assert!(debug_str.contains("**REDACTED**"));
        assert!(!debug_str.contains("255"));
    }

    #[test]
    fn test_zeroize_explicit() {
        let mut arr = ProtectedArray::<8>::new([0xaa; 8]);
        arr.zeroize();
        assert_eq!(&arr[..], &[0u8; 8]);
    }
}
