use subtle::ConstantTimeEq;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_slices() {
        let a = b"secret-token-value-123";
        let b = b"secret-token-value-123";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_different_lengths() {
        let a = b"short";
        let b = b"longer-string";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_mismatch_at_first_byte() {
        let a = b"x-secret-value";
        let b = b"y-secret-value";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_mismatch_at_last_byte() {
        let a = b"secret-value-1";
        let b = b"secret-value-2";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_empty_slices() {
        assert!(constant_time_eq(&[], &[]));
    }
}

