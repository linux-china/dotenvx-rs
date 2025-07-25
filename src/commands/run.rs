use crate::commands::get_env_file_arg;
use clap::ArgMatches;
use dotenvx_rs::dotenvx;
use std::env;
use std::process::{Command, Stdio};

pub fn run_command(
    command_and_args: &[String],
    command_matches: &ArgMatches,
    profile: &Option<String>,
) -> i32 {
    if command_and_args.len() == 0 {
        eprintln!("Please supply command to run");
        return 1;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    dotenvx::from_path(&env_file).unwrap();
    let command_name = &command_and_args[0];
    let mut command_args: Vec<String> = command_and_args[1..].to_vec();
    command_args.iter_mut().for_each(|arg| {
        if arg.starts_with('$') {
            let env_var_name = if arg.starts_with("${") {
                &arg[2..arg.len() - 1]
            } else {
                &arg[1..]
            };
            if let Ok(value) = env::var(env_var_name) {
                *arg = value.clone();
            }
        }
    });
    let mut command = construct_command(command_name, &command_args);
    let mut child = command
        .spawn()
        .expect("DOTENV-CMD-500: failed to run command");
    child
        .wait()
        .expect("DOTENV-CMD-500: failed to run command")
        .code()
        .unwrap()
}

/// construct std::process::Command with std io inherit
pub fn construct_command(command_name: &str, args: &[String]) -> Command {
    let mut command = Command::new(command_name);
    command
        .envs(env::vars())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for arg in args {
        command.arg(arg);
    }
    command
}
