## Overview

`lsec-ffi` exposes a standard C99 ABI interface for the `lsec` defense-in-depth security engine. It compiles into shared (`.so`, `.dylib`, `.dll`) and static (`.a`) libraries accompanied by native C headers (`include/lsec.h`) for low-level systems programming, process hardening, multi-slot vault containers and foreign function interfaces (FFI).

## Header and Artifacts

| Artifact | Type | Target Path |
| :--- | :--- | :--- |
| `lsec.h` | C99 Header | `include/lsec.h` |
| `liblsec_ffi.so` | Linux Shared Object | `target/release/liblsec_ffi.so` |
| `liblsec_ffi.dylib` | macOS Shared Library | `target/release/liblsec_ffi.dylib` |
| `lsec_ffi.dll` | Windows Dynamic Library | `target/release/lsec_ffi.dll` |
| `liblsec_ffi.a` | Universal Static Library | `target/release/liblsec_ffi.a` |

## Installation

Build the native library and header artifacts using Cargo:

```bash
cargo build --release -p lsec-ffi
```

## Usage

Include `lsec.h` in your C or C++ application:

```c
#include <stdio.h>
#include <string.h>
#include "lsec.h"

int main(void) {
    const uint8_t secret[] = "value";
    lsec_protected_buffer_t *buf = NULL;

    // allocate page-locked memory
    int32_t status = lsec_buffer_new(secret, sizeof(secret) - 1, &buf);
    if (status != LSEC_OK) {
        return 1;
    }

    // wipe and release buffer
    lsec_buffer_wipe(buf);
    lsec_buffer_free(buf);
    return 0;
}
```

Compile and link against `liblsec_ffi`:

```bash
gcc -O2 -I./include main.c -L../../target/release -llsec_ffi -Wl,-rpath,../../target/release -o app
```

## Connected Topics

| Topic | Relationship | Context |
| :--- | :--- | :--- |
| [Core Engine](https://github.com/sfossl/lsec/tree/main/crates/lsec-core) | Underlying Rust Crate | Memory locking and cryptographic algorithms |
| [C Integration Guide](https://github.com/sfossl/lsec/blob/main/.docs/c-integration.md) | Dedicated Documentation | Compiler flags, header symbols and link order |
| [Memory Guard](https://github.com/sfossl/lsec/blob/main/.docs/memguard.md) | Core Primitive | Page-locked memory and zeroization mechanics |
| [API Reference](https://github.com/sfossl/lsec/blob/main/.docs/api-reference.md) | Function Index | Complete C-ABI return codes and struct layouts |
| [Repository Overview](https://github.com/sfossl/lsec) | Workspace Root | Architecture and multi-target ecosystem matrix |
