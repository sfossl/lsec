[Docs Overview](../README.md#documentation) / C Integration

# C Integration

`lsec-ffi` exposes a standard C99 interface for integrating memory protection, vault encryption and TOTP generation into C, C++ and native runtime environments.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Header & Artifacts

- Header file: `crates/lsec-ffi/include/lsec.h`
- Shared library: `target/release/liblsec_ffi.so` (Linux), `liblsec_ffi.dylib` (macOS), `lsec_ffi.dll` (Windows)
- Static library: `target/release/liblsec_ffi.a`

## Building the Shared Library

Build the optimized native shared library:

```bash
cargo build --release -p lsec-ffi
```

## Compilation and Linking

### Linux & macOS

```bash
gcc -O2 -I./crates/lsec-ffi/include \
    main.c -L./target/release -llsec_ffi \
    -Wl,-rpath,./target/release \
    -o app
```

## Minimal Working Example

```c
#include <stdio.h>
#include <string.h>
#include "lsec.h"

int main(void) {
    const uint8_t secret[] = "value";
    lsec_protected_buffer_t *buf = NULL;

    int32_t status = lsec_buffer_new(secret, sizeof(secret) - 1, &buf);
    if (status != LSEC_OK) {
        fprintf(stderr, "buffer alloc failed: %d\n", status);
        return 1;
    }

    size_t len = lsec_buffer_len(buf);
    printf("allocated locked buffer length: %zu\n", len);

    lsec_buffer_wipe(buf);
    lsec_buffer_free(buf);
    return 0;
}
```

## Memory Management Rules

1. Every pointer allocated by `lsec_buffer_new` or returned by `lsec_vault_unseal` must be freed with `lsec_buffer_free()`.
2. Raw byte buffers returned by `lsec_vault_seal` must be deallocated using `lsec_vault_bytes_free(ptr, len)`.
3. Never pass buffers freed with `lsec_buffer_free` back into C-ABI functions.

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [TOTP](totp.md) | Time-based passcodes and Base32 decoding |
| **Next** | [Go Integration](go-integration.md) | CGo bindings and garbage-collector safety |
| **API Reference** | [API Reference: lsec-ffi](api-reference.md#module-lsec-ffi-c-abi) | Complete C function reference and error return codes |
| **Header File** | [`lsec.h`](../crates/lsec-ffi/include/lsec.h) | C99 function and constant definitions |
