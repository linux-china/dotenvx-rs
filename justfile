build:
    cargo build

release:
    cargo build --release
    ls -ls target/release/dotenvx

cli-help:
    cargo run --bin dotenvx -- --help

encrypt:
    cargo run --bin dotenvx -- encrypt

decrypt:
    cargo run --bin dotenvx -- decrypt

demo-sh: build
    ./target/debug/dotenvx run -- ./demo.sh
