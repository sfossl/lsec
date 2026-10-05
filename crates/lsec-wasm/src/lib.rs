#![forbid(unsafe_op_in_unsafe_fn)]

#[no_mangle]
pub extern "C" fn lsec_wasm_is_ready() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_ready() {
        assert_eq!(lsec_wasm_is_ready(), 1);
    }
}

