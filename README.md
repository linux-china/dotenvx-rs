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

- Smaller and faster and written in Rust: the `dotenvx` executable is only 3MB.
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

# .env file specification

Every .env file has three sections: metadata(front matter), public key and environment variables.

Example as following:

```shell
# ---
# uuid: f7580ac5-0b24-4385-b3ff-819225b687f3
# name: identify-your-dotenv-file
# group: com.example.dotenvx
# sign: +1+y3Eio5OHPcp9xiP125qfXl/CX4Zuxhft91aW59WtTjZJoSDmFs4KPZ2nDop07VdYkE8vF2BWuUpneCU1xlA==
# ---
DOTENV_PUBLIC_KEY="02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0"

# Environment variables. MAKE SURE to ENCRYPT them before committing to source control
HELLO=encrypted:BNexEwjKwt87k9aEgaSng1JY6uW8OkwMYEFTwEy/xyzDrQwQSDIUEXNlcwWi6rnvR1Q60G35NO4NWwhUYAaAON1LOnvMk+tJjTQJaM8DPeX2AJ8IzoTV44FLJsbOiMa77RLrnBv7
```

Explanation:

- Metadata section(front matter): starts with `# ---` and ends with `# ---`
- .env file UUID: a unique identifier for the .env file, used to track changes and versions
- sign: a signature for the .env file, used to verify the integrity of the file, and make sure the file is not tampered
- DOTENV_PUBLIC_KEY: the public key used to encrypt data and verify the signature
- Environment variables: the encrypted environment variables, starts with `encrypted:` prefix

In metadata section, you can add any key-value pairs to describe the .env file, such as `name`, `group`, etc.

For `.env.keys` files, and spec is similar, and metadata section and keys section are as following:

```shell
# ---
# uuid: 8499c5c3-cee3-4c94-99a4-9c86b2ed5dd9
# name: input your name here
# group: demo
# ---

#  Private decryption keys. DO NOT commit to source control
DOTENV_PRIVATE_KEY="9e70188d351c25d0714929205df9bxxx"
DOTENV_PRIVATE_KEY_EXAMPLE="a3d15e4b69c4a942c381xxx"
```

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

### Why sign .env file?

The `.env` file still text file, and other people or tools can modify it, and let the application load the modified
`.env` file, which may cause security issues.

For example, you have an email which is a PayPal account to receive payments. Of course, you don't want others to
change the email address to their own PayPal account, and then you will lose your money.

To prevent this, the `.env` file is signed with a signature(secp256k1) and put in the metadata section of the file.
When you load the `.env` file, the CLI will verify the signature with the public key in the `.env` file.

How the signature works:

- The author run `dotenvx encrypt --sign` to sign the `.env` file with the private key,
  and the signature will be added to the metadata section of the file.
- Signature: SHA256 hash of the `.env` trimmed .env file content(without sign line), and then sign the hash with the
  private key to get the signature, and signature is a base64 encoded string and added to the metadata section of the
  file.
- Verification: Load the `.env` file, extract the public key and signature from the metadata section, SHA256 hash
  the .env file trimmed content(without sign line), and then verify the signature with the public key and the hash.

With this signature, you can ensure that the `.env` file is not tampered, and other people/tools can trust the
`.env` file content and use it safely.

### Why introduce `dotenvx --seal` and `dotenvx --unseal`?

dotenvx CLI uses private keys to sign/decrypt the `.env` files, and these private keys are very important and should not
be
leaked to the public.

dotenvx CLI read the private keys from the `$HOME/.env.keys` file or `DOTENV_PRIVATE_KEY`,  `DOTENV_PRIVATE_KEY_XXX`
environment variables, and these private keys are still as plain text, which is not secure enough.

With `dotenvx --seal` and `dotenvx --unseal`, you can encrypt the `$HOME/.env.keys` file with AES256 and a password,
and other people/tools can use the encrypted `.env.keys.aes` file without knowing the password.

**Attention**: You should remember the password, and it will be used by `dotenvx --unseal` to decrypt the
`$HOME/.env.keys.aes` file.

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

