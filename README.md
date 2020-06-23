# A compact Ed25519 implementation for Rust

* Formally-verified Curve25519 field arithmetic
* `no_std`-friendly
* Lightweight
* Zero dependencies if randomness is provided by the application
* Only one portable dependency (`getrandom`) if not
* Can be compiled to WebAssembly/WASI
* Safe and simple Rust interface

## [API documentation](https://docs.rs/ed25519-compact)

## Usage

```rust
    fn test_signature() {
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
            .verify(b"A differnt message", &signature)
            .expect_err("Signature shouldn't verify");

        // All these structures can be viewed as raw bytes simply by dereferencing them:
        let signature_as_bytes: &[u8] = signature.as_ref();
        println!("Signature as bytes: {:?}", signature_as_bytes);
    }
```