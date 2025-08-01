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
    if command_and_args.is_empty() {
        eprintln!("Please supply command to run");
        return 1;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    let command_name = &command_and_args[0];
    let mut command_args: Vec<String> = command_and_args[1..].to_vec();
    run_command_with_dotenvx(command_name, &mut command_args, &env_file)
}

pub fn run_command_line(global_matches: &ArgMatches, profile: &Option<String>) -> i32 {
    let command_line = global_matches.get_one::<String>("command").unwrap();
    let command_and_args = shlex::split(command_line).unwrap();
    let command_name = &command_and_args[0];
    let mut command_args: Vec<String> = command_and_args[1..].to_vec();
    let env_file = if let Some(profile_name) = profile {
        format!(".env.{profile_name}")
    } else {
        ".env".to_string()
    };
    run_command_with_dotenvx(command_name, &mut command_args, &env_file)
}
fn run_command_with_dotenvx(
    command_name: &str,
    command_args: &mut [String],
    env_file: &str,
) -> i32 {
    dotenvx::from_path(env_file).unwrap();
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
    let mut command = construct_command(command_name, command_args);
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
