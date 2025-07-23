Dotenvx Rust SDK/CLI
======================

# dotenvx library

Run `cargo add dotenvx-rs` to add the dotenvx library to your Rust project.

```rust
#[test]
fn test_dotenv_load() {
    // Load the .env file
    dotenvx_rs::dotenv().ok();
    // Check if the environment variable is set
    let value = env::var("HELLO").unwrap();
    println!("HELLO={}", value);
}
```

# References

* [Dotenvx](https://dotenvx.com/): encrypts your .env files–limiting their attack vector while retaining their benefits.
* [ecies-rs](https://github.com/ecies/rs): Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Rust
