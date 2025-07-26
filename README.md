Dotenvx Rust SDK/CLI
======================

What is Dotenvx? [Dotenvx](https://dotenvx.com/) encrypts your .env files - limiting their attack vector while retaining
their benefits.

dotenvx-rs is a Rust command-line toolchain for [dotenvx]() to make .env files secure and easy to use,
and it's also a crate to load encrypted .env files in your Rust applications.

Please read [dotenvx cheat sheet](https://cheatography.com/linux-china/cheat-sheets/dotenvx/) for quick overview.

# dotenvx library

Run `cargo add dotenvx-rs` to add the dotenvx library to your Rust project.

```rust
use dotenvx_rs::dotenvx;

#[test]
fn test_dotenv_load() {
    // Load the .env file
    dotenvx::dotenv().ok();
    // Check if the environment variable is set
    let value = env::var("HELLO").unwrap();
    println!("HELLO={}", value);
}
```

# dotenvx CLI

### Get Started

- Install: Run `cargo binstall dotenvx-rs` or `brew install linux-china/tap/dotenvx-rs` or download it
  from [releases](https://github.com/linux-china/dotenvx-rs/releases)
- Initialize: Run `dotenvx init` to create `.env` and `.env.keys` files in the current directory.
- Encrypt .env file: Run `dotenvx encrypt` to encrypt the `.env` file.
- Decrypt .env file: Run `dotenvx decrypt` to decrypt the `.env` file.

dotenvx Rust CLI is almost a drop-in replacement for the original [dotenvx CLI](https://dotenvx.com/),
with some differences:

- Smaller and faster: less 3M with binary size, faster because Rust rewrite
- Global `--profile` as first citizen to make it easy to manage different environments
- Global private key management: Use `dotenvx init --global` to create a global `$HOME/.env.keys` file and manage
  private keys for different environments by profile style.
- Add `init` sub command to create `.env` and `.env.keys` file
- Add `diff` sub command to compare keys from all .env files
- Easy integration for Rust CLIs to load encrypted .env files
- No ext sub command

### Migrated to dotenvx CLI

If you have .env files already, you just run `dotenvx init`, and dotenvx CLI will create `.env.keys` file
and update .env file with new public key.

# FAQ

### What is profile?

A profile is a way to manage different environments in dotenvx CLI, and you can specify the profile with the following
ways:

- Use `--profile <profile_name>` option to specify the profile, such as `dotenvx -p prod encrypt`
- Get profile from .env file, such as `.env.prod` for `prod` profile, `.env.test` for `test` profile, etc.
- GEt profile from environment variables: `NODE_ENV`, `RUN_ENV`, `APP_ENV`, `SPRING_PROFILES_ACTIVE`.

Different profiles have different `.env` files, such as `.env.prod`, `.env.test`, `.env.dev`, etc.,  
and different profiles have different private keys for encryption and decryption,
such as `DOTENV_PRIVATE_KEY_PROD`, `DOTENV_PRIVATE_KEY_TEST`, etc.

If no profile is specified, the CLI will use the `.env` file and `DOTENV_PRIVATE_KEY` private key by default.

**Tips**: you can create alias for a profile, such as `alias prod-env='dotenvx -p prod'` to manage secrets for
production profile.

### How CLI to find private key?

The CLI looks for the private key in the following order:

For example the private key name is `DOTENVX_PRIVATE_KEY_PROD`:

- Find from `.env.keys` file in the current directory and parent directories recursively, and `$HOME/.env.keys` is
  checked as well.
- Find from `DOTENVX_PRIVATE_KEY_PROD` environment variable

If you want to use unified private key for different environments, and you can use following environment variables:

- `DOTENVX_PRIVATE_KEY` for `.env` file and local development
- `DOTENVX_PRIVATE_KEY_PROD` for `.env.prod` file and production
- `DOTENVX_PRIVATE_KEY_TEST` for `.env.test` file and testing

**Tips**: you can use `dotenvx init --stdout` to generate key pair.

### How to manage private keys?

dotenvx CLI uses profile style to manage private keys, and you can use following practices to manage private keys:

- Project specific private keys: use `dotenvx init` to create `.env.keys` file in the project's directory
- Global private: use `dotenvx init --global` to create a global `$HOME/.env.keys` file to manage unified private keys
  for different projects.
- Team/Production global private keys: use `ABC_TEST`, `REGION1_PROD` as profile names to manage private keys for
  different teams, products or regions.

### How to rotate/reset key pairs for env files?

If you don't want to use private key from environment variables, or you want to rotate your private key,
you can use the `dotenvx rotate` command to generate a new key pair, examples:

- Rotate the private key for `.env` file: `dotenvx rotate`
- Rotate the private key for `.env.prod` file: `dotenvx rotate -f .env.prod`

### How to decrypt dotenv file and export variables as environment variables?

You can use the `dotenvx decrypt --export` command to decrypt the dotenv file and output as shell script.

- `eval $(dotenvx decrypt --export)` command will decrypt dotenv file and export the variables to the current shell.
- `eval $(dotenvx get key --format shell)` command will export key's value from .env as environment variable.

**Tips**: if you use [direnv](https://direnv.net/), and you can add `eval $(dotenvx decrypt --export)` to the `.envrc`
file to automatically load .env as the environment variables when you enter the directory.

### How to add encrypted key-value pair from CLI?

You can use `dotenvx set <key> <value>` to write an encrypted key-value pair to the `.env` file.
If you don't want to shell history to record the sensitive value,
you can use `dotenvx set <key> -` to read the value from standard input (stdin),
and press Ctrl+D on Linux/macOS or Ctrl+Z on Windows to finish input.

**Tips**: you can use `cat xxx.pem | dotenvx set my_private_pem -` to encrypt any text file as a key-value pair in the
`.env` file.

### How to check key's difference between .env files?

You can use the `dotenvx diff key1,key2` command to display the difference values from .env files,
and dotenvx will search all .env files in the current directory and compare the values of the specified keys.

**Tips**: you can use `dotenvx diff --format csv key1,key2` to output the difference in CSV format,
and use other tools to process the CSV data for further analysis.

### How to use dotenvx CLI in GitHub Actions?

Please add `uses: linux-china/setup-dotenvx@main` to your workflow file to set up dotenvx CLI,
and add `DOTENV_PRIVATE_KEY` secret to the `Repository secrets`.

Example workflow file to use dotenvx cli:

```yaml
jobs:
  dotenvx-demo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: linux-china/setup-dotenvx@main
      - run: npm install
      - run: $HOME/.cargo/bin/dotenvx run -- node index.js
        env:
          DOTENV_PRIVATE_KEY: ${{ secrets.DOTENV_PRIVATE_KEY }}
```

If you use [act](https://github.com/nektos/act) for local GitHub Actions test, please use
`act -j dotenvx-demo --secret-file .env.keys`.

# Credits

* [Dotenvx](https://dotenvx.com/): encrypts your .env files–limiting their attack vector while retaining their benefits.
* [ecies-rs](https://github.com/ecies/rs): Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Rust
* [dotenvy](https://github.com/allan2/dotenvy): a well-maintained fork of the dotenv crate

