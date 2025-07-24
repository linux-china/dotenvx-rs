<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Task Keeper Changelog

## [0.1.2] - 2025-07-24

### Added

- Add `dotenvx init --stdout` to generate key pair and print to stdout
- Add `dotenvx decrypt --export` to decrypt dotenv file and export variables as shell script
- Add `.aiignore` file to ignore AI-generated files
- Add `dotenvx set <key> <value> --stdout` to output the key-value(encrypted) pair to stdout
- Add `dotenvx get <key> <encrypted_value>` to output the key-value(plain) pair to stdout

## [0.1.1] - 2025-07-23

### Added

- Initial version
- Add most commands from `dotenvx` Node.js CLI
- Add `init` sub command to create `.env` and `.env.keys` file
