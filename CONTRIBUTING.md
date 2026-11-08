# Contributing Guidelines

Pull requests and issues are welcome. Contributions must adhere to the architectural invariants and coding standards below.

## Code Standards

| Invariant | Requirement |
| :--- | :--- |
| **Dependencies** | Minimal dependencies. Standard audited cryptographic primitives (`zeroize`, `argon2`, `chacha20poly1305`, `aes-gcm`, `subtle`) exclusively. |
| **Rust Version** | Rust 2021 edition (stable 1.75 or higher). |
| **Memory Isolation** | Memory containing plaintext or secrets must be held in `ProtectedBuffer` with guaranteed zeroization on drop. |
| **Comments** | Minimal natural comments (lowercase, 3-7 words per item) explaining invariants, never restating obvious code. |
| **Formatting & Lints** | All code must format cleanly with `cargo fmt` and pass `cargo clippy --all-targets -- -D warnings` with zero warnings. |
| **Cross-Platform Safety** | FFI exports must be panic-safe (`catch_unwind`), null-checked and memory-safe across C, Go and WebAssembly. |

## Verification Checklist

Before opening a pull request, run local verification:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node bindings/js/test.mjs
(cd bindings/go && go test -v ./...)
```

All automated checks must pass before a pull request can be merged.

## Commit Guidelines

Use concise, direct commit messages without prefixes, capitalization flags or emojis
- `add feature description`
- `fix defect description`
- `update component description`
