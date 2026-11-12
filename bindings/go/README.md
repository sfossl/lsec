## Overview

`bindings/go` provides an idiomatic Go package for the `lsec` defense-in-depth security engine, integrating native page-locked memory, process dump suppression, multi-slot vault containers, local envelope encryption and TOTP verification via Cgo over the `lsec-ffi` shared library.

## Installation

```bash
go get github.com/sfossl/lsec/bindings/go
```

## Prerequisites

The Go package links dynamically against `liblsec_ffi`. Build the native library before running or testing:

```bash
cargo build --release -p lsec-ffi
```

For development or custom library locations, point Cgo to the build directory:

```bash
export CGO_LDFLAGS="-L/path/to/lsec/target/release -Wl,-rpath,/path/to/lsec/target/release"
go test -v ./...
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/sfossl/lsec/bindings/go"
)

func main() {
	passphrase := []byte("passphrase")
	data := []byte("data")

	// seal payload with authenticated encryption
	sealed, err := lsec.Seal(data, passphrase, lsec.CipherChaCha20Poly1305)
	if err != nil {
		panic(err)
	}

	// decrypt back into page-locked buffer
	buf, err := lsec.Unseal(sealed, passphrase)
	if err != nil {
		panic(err)
	}
	defer buf.Free()

	fmt.Printf("unsealed length: %d\n", buf.Len())
}
```

## Memory Management

* **Garbage collection**: Each `Buffer` registers a `runtime.SetFinalizer` callback to automatically release memory if dropped without an explicit free.
* **Deterministic cleanup**: Call `buf.Free()` or `buf.Wipe()` immediately after completing sensitive operations to ensure immediate zeroization without waiting for GC passes.
* **Heap isolation**: Underlying bytes reside in locked native memory pages protected against crash dumps and memory swapping.

## Connected Topics

| Topic | Relationship | Context |
| :--- | :--- | :--- |
| [C-ABI Shared Library](https://github.com/sfossl/lsec/tree/main/crates/lsec-ffi) | Native Dependency | C header and shared library compiled from Rust |
| [Go Integration Guide](https://github.com/sfossl/lsec/blob/main/.docs/go-integration.md) | Dedicated Documentation | Cgo flags, GC finalizers and pointer safety |
| [Go Package Reference](https://pkg.go.dev/github.com/sfossl/lsec/bindings/go) | Registry Documentation | Exported types, functions and documentation |
| [API Reference](https://github.com/sfossl/lsec/blob/main/.docs/api-reference.md) | Function Index | Full API specification across all runtimes |
| [Repository Overview](https://github.com/sfossl/lsec) | Workspace Root | Architecture and multi-target ecosystem matrix |
