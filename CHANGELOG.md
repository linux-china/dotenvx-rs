<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Task Keeper Changelog

## [0.2.2] - 2025-07-25

### Added

- Add `dotenvx decrypt <value>` to decrypt the encrypted value and output it to stdout
- Add `dotenvx -c 'command'` to run command with injected environment variables, compatible with shell style.
- Add compatible APIs from `dotenvy` crate
- Docs: add direnv integration

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
