# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs` is the crate root; core modules live in `src/` (e.g., `ed25519.rs`, `x25519.rs`, `field25519.rs`, `edwards25519.rs`, `pem.rs`, `sha512.rs`).
- Build configuration lives in `Cargo.toml`; wasm-specific flags are in `.cargo/config.toml`.
- CI expectations are defined in `.github/workflows/rust.yml`.

## Build, Test, and Development Commands
- `cargo build` — build the crate with default features.
- `cargo test` — run inline unit tests in `src/*.rs`.
- `cargo build --no-default-features` — verify `no_std`-friendly builds (mirrors CI).
- `cargo test --features=pem,traits,self-verify,blind-keys,opt_size` — exercise optional feature sets.
- `cargo build --features=disable-signatures` — ensure the X25519-only build path compiles.

## Coding Style & Naming Conventions
- Rust 2018 edition; no custom formatter config is present, so use `cargo fmt` with defaults.
- File/module names are `snake_case`; public types use `PascalCase`; constants use `SCREAMING_SNAKE_CASE`.
- Keep APIs `no_std`-compatible unless behind a feature flag (`std`, `random`, `pem`, etc.).

## Testing Guidelines
- Tests are embedded with `#[test]` in the relevant modules (e.g., `src/ed25519.rs`, `src/x25519.rs`, `src/pem.rs`).
- Add tests adjacent to the code you change, especially for cryptographic edge cases and parsing.
- Run the feature-matrix commands above before submitting changes.

## Commit & Pull Request Guidelines
- Commit subjects in history are short and imperative (e.g., “Bump”, “Update …”, “Fix …”); follow the same style without prefixes.
- PRs should describe behavior changes, list tests run (and feature flags), and call out any public API or `no_std` impact.
- Link related issues when applicable.

## Security & Configuration Notes
- The `random` feature uses `getrandom`; keep deterministic seeding for tests or reproducibility.
- For `wasm32-unknown-unknown`, `.cargo/config.toml` sets `getrandom_backend="wasm_js"`; keep this in sync with any wasm changes.
- Prefer feature flags for optional functionality (`pem`, `traits`, `x25519`, `disable-signatures`, `opt_size`).
