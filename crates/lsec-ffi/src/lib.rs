#![forbid(unsafe_op_in_unsafe_fn)]

#[no_mangle]
pub extern "C" fn lsec_version_major() -> u32 {
    0
}

#[no_mangle]
pub extern "C" fn lsec_version_minor() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn lsec_version_patch() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_exports() {
        assert_eq!(lsec_version_major(), 0);
        assert_eq!(lsec_version_minor(), 1);
        assert_eq!(lsec_version_patch(), 0);
    }
}

