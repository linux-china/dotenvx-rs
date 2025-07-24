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

Run `cargo install dotenvx-rs` to install the dotenvx CLI Rust edition,
and run `dotenvx set KEY1 VALUE1` to create `.env` file with dotenvx encrypted format.

dotenvx Rust CLI is almost a drop-in replacement for the original [dotenvx CLI](https://dotenvx.com/),
with some differences:

- Smaller and faster: less 2M binary size, faster because Rust rewrite.
- No ext sub command
- Add init sub command to create `.env` and `.env.keys` file

# FAQ

### How CLI to find private key?

The CLI looks for the private key in the following order:

For example the private key name is `DOTENVX_PRIVATE_KEY_PROD`:

- Find from `.env.keys` file in the current directory
- Find from `DOTENVX_PRIVATE_KEY_PROD` environment variable
- Use `DOTENVX_PRIVATE_KEY` from `.env.keys` file in the current directory
- Use `DOTENVX_PRIVATE_KEY` environment variable

If you want to use unified private key for different environments, ad you can set environment variables:

- `DOTENVX_PRIVATE_KEY` for local development
- `DOTENVX_PRIVATE_KEY_PROD` for production
- `DOTENVX_PRIVATE_KEY_TEST` for testing

### How to rotate/reset key pairs for env files?

If you don't want to use private key from environment variables, or you want to rotate your private key,
you can use the `dotenvx rotate` command to generate a new key pair, examples:

- Rotate the private key for `.env` file: `dotenvx rotate`
- Rotate the private key for `.env.prod` file: `dotenvx rotate -f .env.prod`

# References

* [Dotenvx](https://dotenvx.com/): encrypts your .env files–limiting their attack vector while retaining their benefits.
* [ecies-rs](https://github.com/ecies/rs): Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Rust
