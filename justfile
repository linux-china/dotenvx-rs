build:
    cargo build

release:
    cargo build --release
    ls -ls target/release/dotenvx
    cp target/release/dotenvx ~/bin/dotenvx

cli-help:
    cargo run --bin dotenvx -- --help

encrypt:
    cargo run --bin dotenvx -- encrypt

decrypt:
    cargo run --bin dotenvx -- decrypt --stdout

keypair:
    cargo run --bin dotenvx -- keypair -f .env.example

list-env-files:
    cargo run --bin dotenvx -- ls

get-hello:
    cargo run --bin dotenvx -- get HELLO

get-all:
    cargo run --bin dotenvx -- get

set-nick:
    cargo run --bin dotenvx -- set nick "Jackie Chan"

rotate-example:
    cargo run --bin dotenvx -- rotate -f .env.example

demo-sh: build
    ./target/debug/dotenvx run -- ./demo.sh
