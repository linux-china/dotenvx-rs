use clap::ArgMatches;
use std::path::PathBuf;

pub fn linter_command(_: &ArgMatches) {
    match lint() {
        Ok(0) => {}
        // warnings are printed by the linter
        Ok(_) => std::process::exit(1),
        Err(e) => {
            eprintln!("Failed to lint env files: {e}");
            std::process::exit(1);
        }
    }
}

/// Lint the env files in the current directory, returns the number of warnings.
pub fn lint() -> anyhow::Result<usize> {
    use dotenv_analyzer::LintKind;
    use dotenv_linter::CheckOptions;
    use dotenv_linter::check;
    let current_dir = std::env::current_dir()?;
    let mut excludes: Vec<&PathBuf> = vec![];
    let env_keys_file = current_dir.join(".env.keys");
    if env_keys_file.exists() {
        excludes.push(&env_keys_file);
    }
    let options = CheckOptions {
        files: vec![&current_dir],
        // dotenvx writes the values with double quotes, see `dotenv_double_quote`
        ignore_checks: vec![LintKind::UnorderedKey, LintKind::QuoteCharacter],
        exclude: excludes,
        quiet: false,
        recursive: false,
        schema: None,
    };
    check(&options, &current_dir).map_err(|e| anyhow::anyhow!(e.to_string()))
}
