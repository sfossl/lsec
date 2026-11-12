[Docs Overview](../README.md#documentation) / Memory Guard

# Memory Guard

The `memguard` module provides OS page-aligned locked memory buffers (`ProtectedBuffer`) pinned to physical RAM, excluded from core dumps and deterministically zeroized on drop.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Guarantees

| Property | Mechanism |
| :--- | :--- |
| **Page-Aligned Allocation** | Aligns allocations to OS page boundaries (4096 bytes) to prevent cross-buffer unlocking races. |
| **Physical RAM Pinning** | `mlock` on POSIX and `VirtualLock` on Windows prevent the OS from writing secrets to swap space. |
| **Crash Dump Exclusion** | Linux `madvise(MADV_DONTDUMP)` prevents secret buffers from appearing in user-space core dumps. |
| **Volatile Zeroization** | Volatile writes and compiler memory barriers prevent dead-store elimination during memory wipes. |

## Lifecycle

```rust
use lsec_core::memguard::ProtectedBuffer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // allocate locked memory
    let mut buffer = ProtectedBuffer::new(b"value")?;

    // read and mutate via slice
    assert_eq!(&buffer[..], b"value");
    buffer.as_mut_slice()[0] = b'V';

    // explicit zeroization
    buffer.wipe();
    Ok(())
}
```

## Zero-Length & Empty Buffers

Zero-length buffers do not invoke kernel memory locking syscalls. They return an empty buffer safely without system overhead:

```rust
let empty = ProtectedBuffer::new(b"")?;
assert!(empty.is_empty());
```

## Stack Allocation: ProtectedArray<N>

For fixed-size secrets (such as 256-bit symmetric keys, 96-bit nonces and HMAC seeds), `ProtectedArray<const N: usize>` provides stack allocation with volatile zeroization on drop, avoiding the virtual memory overhead of page-locked allocations.

| Property | `ProtectedBuffer` | `ProtectedArray<N>` |
| :--- | :--- | :--- |
| **Storage Location** | Page-aligned heap (`mmap`/`VirtualAlloc`) | Stack memory |
| **Kernel Syscalls** | `mlock` / `VirtualLock` / `madvise` | Zero syscalls |
| **Allocation Overhead** | 4096-byte OS page boundary | `N` bytes (zero heap overhead) |
| **Lock Quota** | Counts against `RLIMIT_MEMLOCK` | Excluded from lock limits |
| **Zeroization** | Volatile memory overwrite | Volatile overwrite and compiler memory barrier |
| **Primary Use Case** | Variable-length payloads and decrypted files | Ephemeral keys, nonces and HMAC seeds |

### Usage

```rust
use lsec_core::memguard::ProtectedArray;

// fixed 32-byte key buffer
let key = ProtectedArray::<32>::new([0x42; 32]);

// scoped access with closure
key.with_exposed(|raw_slice| {
    assert_eq!(raw_slice.len(), 32);
});

// copy from slice with length validation
let from_slice = ProtectedArray::<16>::from_slice(b"0123456789abcdef")?;
assert_eq!(from_slice.len(), 16);
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [Getting Started](getting-started.md) | Project installation and quickstart |
| **Next** | [Vault](vault.md) | Encrypted container format and atomic filesystem storage |
| **API Reference** | [API Reference: memguard](api-reference.md#module-lsec-corememguard) | Function signatures and `MemguardError` variants |
| **C-ABI** | [C Integration](c-integration.md) | `lsec_buffer_new`, `lsec_buffer_wipe` and `lsec_buffer_free` |
