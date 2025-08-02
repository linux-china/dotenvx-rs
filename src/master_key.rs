use clap::{Arg, ArgAction, ArgMatches, Command};
use dirs::home_dir;
use std::env;
use std::process::Stdio;

pub const VERSION: &str = "0.3.2";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = build_global_keys_app();
    let matches = app.get_matches();
    let mut raw_args: Vec<String> = env::args().skip(1).collect();
    // run the sub-commands
    if let Some((command, command_matches)) = matches.subcommand() {
        match command {
            "ls" => {
                let dotenvx_home = home_dir().unwrap().join(".dotenvx");
                raw_args.push(dotenvx_home.to_str().unwrap().to_owned());
            }
            "get" | "set" | "encrypt" | "decrypt" => {
                let profile_offset = raw_args
                    .iter()
                    .position(|x| *x == "-p" || *x == "--profile");
                if let Some(offset) = profile_offset {
                    let profile_value = raw_args.get(offset + 1).cloned().unwrap_or_default();
                    if !profile_value.starts_with("g_") {
                        raw_args.remove(offset + 1); // Remove the profile value
                        raw_args.insert(offset + 1, format!("g-{profile_value}"));
                    }
                } else {
                    raw_args.insert(0, "-p".to_string());
                    raw_args.insert(1, "g_default".to_string());
                }
            }
            &_ => println!("Unknown command"),
        }
    }
    let mut command = std::process::Command::new("dotenvx");
    command
        .envs(env::vars())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .args(raw_args);
    let mut child = command
        .spawn()
        .expect("DOTENV-CMD-500: failed to run command");
    let exit_code = child
        .wait()
        .expect("DOTENV-CMD-500: failed to run command")
        .code()
        .unwrap();
    std::process::exit(exit_code);
}

fn get_profile(global_matches: &ArgMatches) -> Option<String> {
    let profile = global_matches
        .get_one::<String>("profile")
        .map(|s| s.to_owned());
    if let Some(profile_name) = profile {
        if profile_name.starts_with("g_") {
            Some(profile_name)
        } else {
            Some(format!("g_{profile_name}"))
        }
    } else {
        Some("g_default".to_string())
    }
}

pub fn build_global_keys_app() -> Command {
    let set_command = Command::new("set")
        .about("Set a single credential")
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
        .arg(Arg::new("key").help("key's name").index(1).required(true))
        .arg(
            Arg::new("value")
                .help("Value")
                .required(false)
                .index(2)
                .num_args(1),
        )
        .arg(
            Arg::new("clipboard")
                .long("clipboard")
                .help("Set key's value from clipboard")
                .action(ArgAction::SetTrue),
        );
    let get_command = Command::new("get")
        .about("Return a single credential")
        .arg(
            Arg::new("all")
                .long("all")
                .help("include all machine envs as well")
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
                .help("format of the output (json, shell) (default: \"json\")")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("override")
                .long("override")
                .help("override existing env variables (by default, existing env vars take precedence over .env files)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pretty-print")
                .long("pretty-print")
                .help("pretty print output")
                .action(ArgAction::SetTrue),
        );
    let encrypt_command = Command::new("encrypt")
        .about("convert .env file(s) to encrypted .env file(s)")
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
            Arg::new("value")
                .help("Decrypt the encrypted value. If different environment, please use `dotnenvx -p <profile> decrypt`")
                .index(1)
                .required(false),
        );
    let ls_command = Command::new("ls").about("print all global .env files");
    Command::new("mkey")
        .version(VERSION)
        .author("linux_china <libing.chen@gmail.com>")
        .about("mkey: Effortlessly manage your credentials, just like using a master key")
        .arg(
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Profile to use, such as 'default'(default), 'github', 'ai', 'self' etc.")
                .num_args(1)
                .required(false),
        )
        .arg(
            Arg::new("command")
                .short('c')
                .long("command")
                .help("Run the command with injected credentials from .env file")
                .num_args(1..)
                .required(false),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output, and you can use NO_COLOR env variable too.")
                .action(ArgAction::SetTrue),
        )
        .subcommand(set_command)
        .subcommand(get_command)
        .subcommand(encrypt_command)
        .subcommand(decrypt_command)
        .subcommand(ls_command)
}
