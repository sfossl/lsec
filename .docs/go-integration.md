[Docs Overview](../README.md#documentation) / Go Integration

# Go Integration

`bindings/go` provides an idiomatic Go package using CGo over the `lsec-ffi` C-ABI.

### Documentation Guides
[Getting Started](getting-started.md) | [Memory Guard](memguard.md) | [Vault](vault.md) | [TOTP](totp.md) | [C Integration](c-integration.md) | [Go Integration](go-integration.md) | [WebAssembly](wasm-integration.md) | [API Reference](api-reference.md)

## Installation

```bash
go get github.com/sfossl/lsec/bindings/go
```

## Prerequisites

The Go package links against `liblsec_ffi`. Ensure the native library is built and accessible in your library search path:

```bash
cargo build --release -p lsec-ffi
```

If `liblsec_ffi` is installed in a system directory (`/usr/local/lib`), standard `go build` works directly. For local development or vendoring, configure `CGO_LDFLAGS`:

```bash
export CGO_LDFLAGS="-L/path/to/lsec/target/release -Wl,-rpath,/path/to/lsec/target/release"
go test -v ./...
```

## Lifecycle and Memory Safety

The Go `Buffer` struct manages an underlying C-allocated page-locked buffer:

- **Garbage Collection**: Each `Buffer` registers a `runtime.SetFinalizer` callback to free unreferenced memory automatically.
- **Explicit Freeing**: For deterministic zeroization, call `buf.Free()` or `buf.Wipe()` immediately after use.
- **Deref Safety**: Buffer accessors call `runtime.KeepAlive(b)` to prevent premature GC sweeps during native memory read operations.

## Minimal Working Example

```go
package main

import (
	"fmt"

	"github.com/sfossl/lsec/bindings/go"
)

func main() {
	passphrase := []byte("passphrase")
	data := []byte("data")

	sealed, err := lsec.Seal(data, passphrase, lsec.CipherChaCha20Poly1305)
	if err != nil {
		panic(err)
	}

	buf, err := lsec.Unseal(sealed, passphrase)
	if err != nil {
		panic(err)
	}
	defer buf.Free()

	fmt.Printf("unsealed %d bytes\n", buf.Len())
}
```

---

## Connected Topics

| Context | Destination | Description |
| :--- | :--- | :--- |
| **Previous** | [C Integration](c-integration.md) | C-ABI headers and shared library builds |
| **Next** | [WebAssembly](wasm-integration.md) | Node.js and browser WebAssembly SDK |
| **API Reference** | [API Reference: Go Bindings](api-reference.md#module-bindingsgo) | Go struct definitions, constructors and methods |
| **Source Code** | [`lsec.go`](../bindings/go/lsec.go) | CGo wrapper implementation |
