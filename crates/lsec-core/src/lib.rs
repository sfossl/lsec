#![forbid(unsafe_op_in_unsafe_fn)]

//! local security engine: locked memory, zeroization, vault storage, totp

pub mod config;
pub mod crypto;
pub mod memguard;
pub mod process;
pub mod totp;
pub mod vault;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn lsec_host_random(ptr: *mut u8, len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn wasm_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let res = unsafe { lsec_host_random(buf.as_mut_ptr(), buf.len()) };
    if res == 0 {
        Ok(())
    } else {
        let code = core::num::NonZeroU32::new(getrandom::Error::CUSTOM_START).unwrap();
        Err(getrandom::Error::from(code))
    }
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(wasm_getrandom);
