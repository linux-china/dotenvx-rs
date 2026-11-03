use crate::commands::get_env_file_arg;
use clap::ArgMatches;
use dotenvx_rs::dotenvx;
use std::env;
use std::process::{Command, ExitStatus, Stdio};

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
    // `-f` or `-p` given: the env file must exist, otherwise the command would run without its variables (review #9)
    let is_explicit = command_matches
        .try_get_one::<String>("env-file")
        .ok()
        .flatten()
        .is_some()
        || profile.is_some();
    let command_name = &command_and_args[0];
    let mut command_args: Vec<String> = command_and_args[1..].to_vec();
    run_command_with_dotenvx(command_name, &mut command_args, &env_file, is_explicit)
}

pub fn run_command_line(global_matches: &ArgMatches, profile: &Option<String>) -> i32 {
    // `-c` accepts one or more values: `-c "ls -la"` or `-c ls -la`
    let command_line = global_matches
        .get_many::<String>("command")
        .map(|values| values.cloned().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let Some(command_and_args) = shlex::split(&command_line) else {
        eprintln!("Invalid command line (unbalanced quotes?): {command_line}");
        return 1;
    };
    let Some((command_name, command_args)) = command_and_args.split_first() else {
        eprintln!("Please supply command to run");
        return 1;
    };
    let mut command_args: Vec<String> = command_args.to_vec();
    let env_file = get_env_file_arg(global_matches, profile);
    let is_explicit = global_matches
        .try_get_one::<String>("env-file")
        .ok()
        .flatten()
        .is_some()
        || profile.is_some();
    run_command_with_dotenvx(command_name, &mut command_args, &env_file, is_explicit)
}

fn run_command_with_dotenvx(
    command_name: &str,
    command_args: &mut [String],
    env_file: &str,
    is_explicit: bool,
) -> i32 {
    if !std::path::Path::new(env_file).exists() {
        if is_explicit {
            eprintln!("Failed to load {env_file}: file not found");
            return 1;
        }
        // the default .env is optional
    } else if let Err(e) = dotenvx::from_path(env_file) {
        eprintln!("Failed to load {env_file}: {e}");
        return 1;
    }
    add_env_alias();
    command_args.iter_mut().for_each(|arg| {
        if let Some(env_var_name) = env_var_reference(arg)
            && let Ok(value) = env::var(env_var_name)
        {
            *arg = value;
        }
    });
    let mut command = construct_command(command_name, command_args);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("DOTENV-CMD-500: failed to run command {command_name}: {e}");
            return 1;
        }
    };
    match child.wait() {
        Ok(status) => get_exit_code(&status),
        Err(e) => {
            eprintln!("DOTENV-CMD-500: failed to wait for command {command_name}: {e}");
            1
        }
    }
}

/// Name of the variable when `arg` is exactly `$NAME` or `${NAME}`, otherwise `None`.
fn env_var_reference(arg: &str) -> Option<&str> {
    let name = if let Some(rest) = arg.strip_prefix("${") {
        rest.strip_suffix('}')?
    } else {
        arg.strip_prefix('$')?
    };
    crate::commands::is_valid_env_key(name).then_some(name)
}

pub fn get_exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else {
        // On Unix, process was terminated by signal
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                std::process::exit(128 + signal);
            }
        }
        1
    }
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

pub fn add_env_alias() {
    if let Ok(nats_url) = env::var("NATS_SERVER") {
        unsafe {
            env::set_var("NATS_URL", nats_url);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn test_env_var_reference() {
        assert_eq!(env_var_reference("$HOME"), Some("HOME"));
        assert_eq!(env_var_reference("${API_TOKEN}"), Some("API_TOKEN"));
        for arg in ["${", "$", "${}", "${FOO}bar", "$FOO/bar", "plain", "${FOO"] {
            assert_eq!(env_var_reference(arg), None, "{arg}");
        }
    }

    #[test]
    fn test_get_exit_code() {
        let status = Command::new("sh").args(["-c", "exit 0"]).status().unwrap();
        assert_eq!(get_exit_code(&status), 0);
        let status = Command::new("sh").args(["-c", "exit 42"]).status().unwrap();
        assert_eq!(get_exit_code(&status), 42);
    }

    #[test]
    fn test_construct_command_passes_args_verbatim() {
        let args = vec![
            "-c".to_string(),
            "printf '%s|%s' \"$0\" \"$1\"".to_string(),
            "with space".to_string(),
            "$NOT_EXPANDED".to_string(),
        ];
        let output = construct_command("sh", &args)
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "with space|$NOT_EXPANDED"
        );
    }
}
