<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Task Keeper Changelog

## [0.3.2] - 2025-08-01

### Added

- Add `dotenvx --no-color` to disable colored output, or use `NO_COLOR=1` environment variable
- Add `--all`, `--override` and `pretty-print` flags for `dotenvx get` sub command
- Add `dotenvx decrypt --dump` to decrypt the items from the .env file and output them to stdout as json format

`dotenvx decrypt --dump` is useful for the languages that have no dotenvx library,
and you can construct the command and execute it, and resolve the json output.

## [0.3.1] - 2025-07-28

### Added

- Add password confirm for `dotenvx --seal`
- Add `dotenvx encrypt --keys <keys>` to encrypt the specified keys in the .env file
- Add `dotenvx decrypt --keys <keys>` to decrypt the specified keys in the .env file
- Add  `application.properties` support for Spring Boot applications

```shell
$ dotenvx encrypt -f application.properties --keys spring.datasource.password
$ dotenvx decrypt -f application.properties --keys spring.datasource.password
```

`application.properties` example:

```properties
# ---
# uuid: 019853c1-92a5-7902-8a0c-13d9d55a0566
# ---

dotenv.public.key=02e8d78f0da7fc3b529d503edd933ed8cdc79dbe5fd5d9bd480f1e63a09905f3b3

# properties
nick=encrypted:BPodujYSdjsczRV7O2nkPPqbS9Q==
```

### Fixed

- Change `--encrypt`, `--plain` to flag for `dotenvx set` command
- Remove double quotes for public/private key's value(hex encoded) in the files

## [0.3.0] - 2025-07-27

### Added

- Add `dotenvx ls` table output to display more information about keys
- Add `dotenvx encrypt --sign` to add signature to the .env file
- Add `dotenvx verify` to verify the signature of the .env file
- Add `dotenvx --seal` and `dotenvx --unseal` to encrypt and decrypt `$HOME/.env.keys` file
- Add .env file spec to add front matter for metadata

```
# ---
# uuid: f7580ac5-0b24-4385-b3ff-819225b687f3
# name: input your name here
# group: demo
# sign: +1+y3Eio5OHPcp9xiP125qfXl/CX4Zuxhft91aW59WtTjZJoSDmFs4KPZ2nDop07VdYkE8vF2BWuUpneCU1xlA==
# ---
DOTENV_PUBLIC_KEY="02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0"

# Environment variables. MAKE SURE to ENCRYPT them before committing to source control
HELLO=encrypted:BNexEwjKwt87k9aEgaSng1JY6uW8OkwMYEFTwEy/xyzDrQwQSDIUEXNlcwWi6rnvR1Q60G35NO4NWwhUYAaAON1LOnvMk+tJjTQJaM8DPeX2AJ8IzoTV44FLJsbOiMa77RLrnBv7

```

## [0.2.2] - 2025-07-25

### Added

- Add `dotenvx decrypt <value>` to decrypt the encrypted value and output it to stdout
- Add `dotenvx -c 'command'` to run command with injected environment variables, compatible with shell style.
- Add `dotenvx keypair --dump` to add public key to .env file and `DOTENV_PRIVATE_KEY` to `.env.keys` file
- Add compatible APIs from `dotenvy` crate
- Docs: add direnv integration
- Some minor improvements and bug fixes

## [0.2.1] - 2025-07-24

### Added

- Add `shell` and `homebrew` installer for Cargo dist
- Add homebrew formula for `dotenvx` CLI: `brew install linux-china/tap/dotenvx-rs`
- Add GitHub Actions workflow for `dotenvx` CLI installation

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

## [0.2.0] - 2025-07-24

### Added

- Add `--profile <profile_name>` option as first citizen to manage different environments
- Add `dotenvx init --stdout` to generate key pair and print to stdout
- Add `dotenvx init --global` to generate `$HOME/.env.keys` for different global environments
- Add `dotenvx diff <keys>` to compare keys from all `.env.keys` files in the current directory
- Add `dotenvx decrypt --export` to decrypt dotenv file and export variables as shell script
- Add `.aiignore` file to ignore AI-generated files
- Add `dotenvx set <key> <value> --stdout` to output the key-value(encrypted) pair to stdout
- Add `dotenvx get <key> <encrypted_value>` to output the key-value(plain) pair to stdout
- Add validation for `dotenvx keypair` command to ensure the key pair is valid
- Add dotenvx CLI cheat sheet: https://cheatography.com/linux-china/cheat-sheets/dotenvx/

## [0.1.1] - 2025-07-23

### Added

- Initial version
- Add most commands from `dotenvx` Node.js CLI
- Add `init` sub command to create `.env` and `.env.keys` file
