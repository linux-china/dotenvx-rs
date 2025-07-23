use clap::ArgMatches;
use dotenvx_rs::dotenvx;
use std::env;
use std::process::{Command, Stdio};

pub fn run_command(command_and_args: &[String], command_matches: &ArgMatches) -> i32 {
    if command_and_args.len() == 0 {
        eprintln!("Please supply command to run");
        return 1;
    }
    let env_file = if let Some(arg_value) = command_matches.get_one::<String>("env-file") {
        arg_value.clone()
    } else {
        ".env".to_string()
    };
    dotenvx::from_path(&env_file).unwrap();
    let command_name = &command_and_args[0];
    let mut command_args: Vec<String> = command_and_args[1..].to_vec();
    command_args.iter_mut().for_each(|arg| {
        if arg.starts_with('$') {
            if let Ok(value) = env::var(&arg[1..]) {
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
