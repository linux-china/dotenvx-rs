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

# dotenvx CLI

Run `cargo install dotenvx-rs` to install the dotenvx CLI Rust edition.

dotenvx Rust CLI is almost a drop-in replacement for the original [dotenvx CLI](https://dotenvx.com/),
with some differences:

- Smaller and faster: less 2M binary size, faster because Rust rewrite.
- No ext sub command

# References

* [Dotenvx](https://dotenvx.com/): encrypts your .env files–limiting their attack vector while retaining their benefits.
* [ecies-rs](https://github.com/ecies/rs): Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Rust
