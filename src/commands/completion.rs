use crate::clap_app::build_dotenvx_app;
use clap::ArgMatches;
use clap_complete::Shell::{Bash, Fish, PowerShell, Zsh};
use clap_complete::{generate, Shell};
use std::io::stdout;

pub fn completion_command(command_matches: &ArgMatches) {
    let shell_name = command_matches
        .get_one::<String>("shell")
        .map(|s| s.to_string())
        .unwrap_or_else(|| Shell::from_env().unwrap_or(Bash).to_string())
        .to_lowercase();
    let mut cmd = build_dotenvx_app();
    if shell_name == "bash" {
        generate(Bash, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name == "zsh" {
        generate(Zsh, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name == "fish" {
        generate(Fish, &mut cmd, "dotenvx", &mut stdout());
    } else if shell_name == "powershell" || shell_name == "pwsh" {
        generate(PowerShell, &mut cmd, "dotenvx", &mut stdout());
    } else {
        eprintln!(
            "Unsupported shell: {shell_name}. Supported shells are bash/zsh/fish/powershell."
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use clap_complete::Shell;

    #[test]
    fn test_get_shell_name() {
        let shell_name = Shell::PowerShell.to_string();
        println!("{shell_name}");
    }
}
