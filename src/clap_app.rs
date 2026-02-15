use clap::{Arg, ArgAction, Command};

pub const VERSION: &str = "0.4.30";

pub fn build_dotenvx_app() -> Command {
    let run_command = Command::new("run")
        .about("Inject env at runtime [dotenvx run -- your-command]")
        .arg(
            Arg::new("env-file")
                .short('f')
                .long("env-file")
                .help("path to your env file (default: .env)")
                .num_args(1)
                .required(false),
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
        .arg(
            Arg::new("all")
                .long("all")
                .help("Include all variables from a .env file")
                .action(ArgAction::SetTrue),
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
                .help("format of the output (text, json, shell, csv, raw) (default: \"text\")")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("override")
                .long("override")
                .help("override existing env variables(always true)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pretty-print")
                .long("pretty-print")
                .help("pretty print output")
                .action(ArgAction::SetTrue),
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
                .help("Encrypt value (default: true)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("plain")
                .short('p')
                .long("plain")
                .help("Store value as plain text (default: false)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Send encrypted value to stdout")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("key").help("key's name").index(1).required(false))
        .arg(
            Arg::new("value")
                .help("Value")
                .index(2)
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("clipboard")
                .long("clipboard")
                .help("Set key's value from the clipboard")
                .action(ArgAction::SetTrue),
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
            Arg::new("keys")
                .long("keys")
                .help("Encrypt only the specified keys(glob support), such as `--keys key1 *token*, *password*`")
                .num_args(0..)
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
            Arg::new("keys")
                .long("keys")
                .help("Decrypt only the specified keys(glob support), such as `--keys key1 *token*, *password*`")
                .num_args(0..)
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
            Arg::new("format")
                .long("format")
                .help("format of the output (text, shell, json, csv) (default: \"text\")")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .help("Dump the decrypted value to stdout with json format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("value")
                .help("Decrypt the encrypted value. If different environment, please use `dotenvx -p <profile> decrypt`")
                .index(1)
                .required(false),
        );
    let keypair_command = Command::new("keypair")
        .visible_alias("kp")
        .about("Validate and print public/private keys for .env file in the current directory")
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
            Arg::new("all")
                .long("all")
                .help("List all keys from $HOME/.dotenvx/.env.keys.json")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("import")
                .long("import")
                .help("Import private key and saved to $HOME/.dotenvx/.env.keys.json")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .help("Dump public key to .env file and private key to .env.keys in current directory")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("public-key")
                .help("Display the key pair for the given public key")
                .index(1)
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
    let link_command = Command::new("link")
        .about("Create a symbolic link with dotenvx")
        .arg(
            Arg::new("command")
                .help("Command linked with dotenvx, such as 'lua', 'mysql', etc.")
                .index(1)
                .required(true),
        );
    let rotate_command = Command::new("rotate")
        .about("Rotate keypair and re-encrypt .env file in the current directory")
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
                .help("Path to your env file (default: .env)")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("group")
                .long("group")
                .help("Group for .env file.")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("name")
                .long("name")
                .help("Name for .env file")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("global")
                .short('g')
                .long("global")
                .help("Create $HOME/.env.keys with profiles(dev, test, perf, sand, stage, prod)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("framework")
                .long("framework")
                .help("Framework to use, such as spring-boot, gofr.")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("stdout")
                .long("stdout")
                .help("Send new key pair to stdout")
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
    let linter_command =
        Command::new("lint").about("Check all .env files in the current directory.");
    let doctor_command = Command::new("doctor").about("Diagnose your .env files and lint");
    let diff_command = Command::new("diff")
        .about("Display keys' values between all .env files")
        .arg(
            Arg::new("keys")
                .help("key names, separated by comma, such as 'key1,key2'")
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
    let sync_command = Command::new("sync")
        .about("Sync variables between .env files")
        .arg(
            Arg::new("source")
                .help("source .env file")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::new("target")
                .help("target .env file")
                .index(2)
                .required(true),
        );
    let completion_command = Command::new("completion")
        .about("Output auto-completion script for bash/zsh/fish/powershell")
        .arg(
            Arg::new("shell")
                .long("shell")
                .help("shell name: bash, zsh, fish, powershell")
                .value_parser(["bash", "zsh", "first", "powershell"])
                .num_args(1)
                .required(false),
        );
    let _cloud_command = Command::new("cloud")
        .about("Dotenv cloud operations, such as registration, send, sync etc.")
        .subcommand(Command::new("signup").about("Sign up an account on Dotenvx cloud"))
        .subcommand(Command::new("me").about("Display current user info on Dotenvx cloud"))
        .subcommand(Command::new("send").about("Send secret to a user on Dotenvx cloud"))
        .subcommand(
            Command::new("sync")
                .about("Send secret to a user on Dotenvx cloud")
                .arg(
                    Arg::new("env-file")
                        .short('f')
                        .long("env-file")
                        .help("path to your env file for synchronization on Dotenvx cloud")
                        .num_args(1)
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("backup")
                .about("Encrypt and backup your $HOME/.dotenvx/.env.keys.aes on Dotenvx cloud"),
        );
    Command::new("dotenvx")
        .version(VERSION)
        .author("linux_china <libing.chen@gmail.com>")
        .about("dotenvx - encrypts your .env files, limiting their attack vector while retaining their benefits.")
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
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output, and you can use NO_COLOR env variable too.")
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
        .subcommand(link_command)
        .subcommand(rotate_command)
        .subcommand(sync_command)
        .subcommand(diff_command)
        .subcommand(linter_command)
        .subcommand(doctor_command)
        .subcommand(completion_command)
    //.subcommand(cloud_command)
}
