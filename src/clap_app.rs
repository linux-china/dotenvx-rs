use clap::{Arg, ArgAction, Command};

pub const VERSION: &str = "0.1.0";

pub fn build_dotenvx_app() -> Command {
    let run_command = Command::new("run")
        .about("inject env at runtime [dotenvx run -- your-command]")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false)
        )
        .arg(
            Arg::new("overload")
                .short('o')
                .long("overload")
                .help("override existing env variables (by default, existing env vars take precedence over .env files)")
                .action(ArgAction::SetTrue)
        );
    let get_command = Command::new("get").about("return a single environment variable");
    let set_command = Command::new("set")
        .about("set a single environment variable")
        .arg(Arg::new("key").help("key's name").index(1).required(true))
        .arg(
            Arg::new("value")
                .help("Value")
                .required(true)
                .index(2)
                .num_args(1),
        );

    let encrypt_command = Command::new("encrypt")
        .about("convert .env file(s) to encrypted .env file(s)")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("send to stdout")
                .action(ArgAction::SetTrue),
        );
    let decrypt_command = Command::new("decrypt")
        .about("convert encrypted .env file(s) to plain .env file(s)")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file(s) (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("send to stdout")
                .action(ArgAction::SetTrue),
        );
    let keypair_command = Command::new("keypair")
        .about("print public/private keys for .env file(s)")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .help("format of the output (json, shell) (default: \"json\")")
                .num_args(1)
                .required(false),
        );
    let ls_command = Command::new("ls")
        .about("print all .env files in a tree structure")
        .arg(
            Arg::new("directory")
                .help("directory to list .env files from (default: \".\")")
                .index(1)
                .required(false),
        );
    let rotate_command = Command::new("rotate")
        .about("rotate keypair(s) and re-encrypt .env file(s)")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        );
    Command::new("dotenvx")
        .version(VERSION)
        .author("linux_china <libing.chen@gmail.com>")
        .about("dotenvx - encrypts your .env files–limiting their attack vector while retaining their benefits.")
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .help("set log level (default: \"info\")")
                .num_args(1..)
                .required(false)
        )
        .subcommand(run_command)
        .subcommand(get_command)
        .subcommand(set_command)
        .subcommand(encrypt_command)
        .subcommand(decrypt_command)
        .subcommand(keypair_command)
        .subcommand(ls_command)
        .subcommand(rotate_command)
}
