![GitHub CI](https://github.com/jedisct1/rust-ed25519-compact/workflows/GitHub%20CI/badge.svg)

# A compact Ed25519 implementation for Rust

* Formally-verified Curve25519 field arithmetic
* `no_std`-friendly
* WebAssembly-friendly
* Compute@Edge-friendly
* Lightweight
* Zero dependencies if randomness is provided by the application
* Only one portable dependency (`getrandom`) if not
* Safe and simple Rust interface

## [API documentation](https://docs.rs/ed25519-compact)

## Example usage

`cargo.toml`:

```toml
[dependencies]
ed25519-compact = "0.1"
```

Example code:

```rust
// A message to sign and verify.
let message = b"test";

// Generates a new key pair using a random seed.
// A given seed will always produce the same key pair.
let key_pair = KeyPair::from_seed(Seed::default());

// Computes a signature for this message using the secret part of the key pair.
let signature = key_pair.sk.sign(message, Some(Noise::default()));

// Verifies the signature using the public part of the key pair.
key_pair
    .pk
    .verify(message, &signature)
    .expect("Signature didn't verify");

// Verification of a different message using the same signature and public key fails.
key_pair
    .pk
    .verify(b"A different message", &signature)
    .expect_err("Signature shouldn't verify");

// All these structures can be viewed as raw bytes simply by dereferencing them:
let signature_as_bytes: &[u8] = signature.as_ref();
println!("Signature as bytes: {:?}", signature_as_bytes);
```

## Cargo features

* `self-verify`: after having computed a new signature, verify that is it valid. This is slower, but improves resilience against fault attacks. It is enabled by default on WebAssembly targets.
* `std`: disables `no_std` compatibility in order to make errors implement the standard `Error` trait.
* `random` (enabled by default): adds `Default` implementations to the `Seed` and `Noise` objects, in order to securely create random keys and noise.
* `traits`: add support for the traits from the `ed25519` and `signature` crates.
* `pem`: add support for importing/exporting keys as OpenSSL-compatible PEM files.
* `blind-keys`: add support for key blinding.
