use clap::{Arg, ArgAction, Command};

pub const VERSION: &str = "0.3.1";

pub fn build_dotenvx_app() -> Command {
    let run_command = Command::new("run")
        .about("Inject env at runtime [dotenvx run -- your-command]")
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
    let get_command = Command::new("get")
        .about("return a single environment variable")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(Arg::new("key").help("key's name").index(1).required(false))
        .arg(
            Arg::new("value")
                .help("the encrypted value")
                .index(2)
                .required(false),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .help("format of the output (json, shell) (default: \"json\")")
                .num_args(1)
                .required(false),
        );
    let set_command = Command::new("set")
        .about("set a single environment variable")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("encrypt")
                .short('c')
                .long("encrypt")
                .help("encrypt value (default: true)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("plain")
                .short('p')
                .long("plain")
                .help("store value as plain text (default: false)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Send encrypted value to stdout")
                .action(ArgAction::SetTrue),
        )
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
            Arg::new("sign")
                .long("sign")
                .help("Add a signature to the encrypted file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Send to stdout")
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
            Arg::new("verify")
                .long("verify")
                .help("Verify the signature of the encrypted file if a signature exists")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Send to stdout")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("export")
                .long("export")
                .help("Output the key-value pairs as shell export commands")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("value")
                .help("Decrypt the encrypted value. If different environment, please use `dotnenvx -p <profile> decrypt`")
                .index(1)
                .required(false),
        );
    let keypair_command = Command::new("keypair")
        .about("Validate and print public/private keys for .env file in current directory")
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
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .help("Dump public key to .env file and private key to .env.keys in current directory")
                .action(ArgAction::SetTrue),
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
        .about("rotate keypair and re-encrypt .env file in current directory")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        );
    let init_command = Command::new("init")
        .about("Create a .env file with a new public/private key pair")
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
                .help("Send new key pair to stdout")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("global")
                .short('g')
                .long("global")
                .help("Create $HOME/.env.keys with profiles(dev, test, perf, sand, stage, prod)")
                .action(ArgAction::SetTrue),
        );
    let verify_command = Command::new("verify")
        .about("Verify the signature of the encrypted .env file")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file(s) (default: .env)")
                .num_args(1)
                .required(false),
        );
    let diff_command = Command::new("diff")
        .about("Display keys' values between all .env files")
        .arg(
            Arg::new("keys")
                .help("key names, seperated by comma, such as 'key1,key2'")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .help("format of the output (text, csv) (default: text)")
                .num_args(1)
                .required(false),
        );
    let cloud_command = Command::new("cloud")
        .about("Dotenv cloud operations, such as registration, sync, audit etc.");
    Command::new("dotenvx")
        .version(VERSION)
        .author("linux_china <libing.chen@gmail.com>")
        .about("dotenvx - encrypts your .env files–limiting their attack vector while retaining their benefits.")
        .arg(
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Profile to use (such as 'dev', 'test', 'stage', 'prod', etc.)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("Run the command with injected environment variables from .env file")
                .num_args(1..)
                .required(false)
        )
        .arg(
            Arg::new("seal")
                .long("seal")
                .help("Seal the $HOME/.env.keys file with AES256 encryption and your password")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("unseal")
                .long("unseal")
                .help("Unseal the $HOME/.env.keys.aes file with AES256 decryption and your password")
                .action(ArgAction::SetTrue)
        )
        .subcommand(init_command)
        .subcommand(run_command)
        .subcommand(get_command)
        .subcommand(set_command)
        .subcommand(encrypt_command)
        .subcommand(decrypt_command)
        .subcommand(verify_command)
        .subcommand(keypair_command)
        .subcommand(ls_command)
        .subcommand(rotate_command)
        .subcommand(diff_command)
        .subcommand(cloud_command)
}
