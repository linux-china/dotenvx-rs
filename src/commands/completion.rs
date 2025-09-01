use crate::clap_app::build_dotenvx_app;
use clap::ArgMatches;
use clap_complete::generate;
use clap_complete::Shell::{Bash, Fish, PowerShell, Zsh};
use std::env;
use std::io::stdout;
use sysinfo::{Pid, ProcessesToUpdate, System};

pub fn completion_command(command_matches: &ArgMatches) {
    let shell_name = command_matches
        .get_one::<String>("shell")
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if let Some(parent_name) = get_parent_process_name() {
                parent_name
            } else {
                get_shell_from_env()
            }
        })
        .to_lowercase();
    let mut cmd = build_dotenvx_app();
    if shell_name.ends_with("bash") {
        generate(Bash, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name.ends_with("zsh") {
        generate(Zsh, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name.ends_with("fish") {
        generate(Fish, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name.ends_with("powershell") || shell_name.ends_with("pwsh") {
        generate(PowerShell, &mut cmd, "dotenvx", &mut stdout());
    } else {
        eprintln!("Unsupported shell: {shell_name}. Supported shells are bash and zsh.");
        std::process::exit(1);
    }
}

fn get_parent_process_name() -> Option<String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let current_pid = std::process::id();
    let current_process = sys.process(Pid::from_u32(current_pid))?;
    let parent_pid = current_process.parent()?;
    let parent_process = sys.process(parent_pid)?;
    Some(parent_process.name().to_string_lossy().to_string())
}

fn get_shell_from_env() -> String {
    if let Ok(shell) = env::var("SHELL") {
        std::path::Path::new(&shell)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    } else if let Ok(comspec) = env::var("ComSpec") {
        std::path::Path::new(&comspec)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        "bash".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_parent_process_name() {
        let parent_name = get_parent_process_name();
        assert!(parent_name.is_some());
        println!("Parent process name: {parent_name:?}");
    }
}
