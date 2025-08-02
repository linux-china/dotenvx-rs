build:
    cargo build --bins

dist-build:
    dist build --target x86_64-apple-darwin

release:
    cargo build --bins --release
    ls -ls target/release/dotenvx
    ls -ls target/release/mkey
    cp target/release/dotenvx ~/bin/dotenvx
    cp target/release/mkey ~/bin/mkey

cli-help:
    cargo run --bin dotenvx -- --help

# generate a new keypair and print it to stdout
init-stdout:
    cargo run --bin dotenvx -- init --stdout

encrypt:
    cargo run --bin dotenvx -- encrypt

decrypt:
    cargo run --bin dotenvx -- decrypt --stdout

decrypt-export:
    cargo run --bin dotenvx -- decrypt --export

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

set-from-stdin:
    cargo run --bin dotenvx -- set nick -

rotate-example:
    cargo run --bin dotenvx -- rotate -f .env.example

demo-sh: build
    ./target/debug/dotenvx run -- ./demo.sh
