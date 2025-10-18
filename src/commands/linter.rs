use clap::ArgMatches;
use std::path::PathBuf;

pub fn linter_command(_: &ArgMatches) {
    lint().unwrap();
}

pub fn lint() -> anyhow::Result<()> {
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
        ignore_checks: vec![LintKind::UnorderedKey],
        exclude: excludes,
        quiet: false,
        recursive: false,
        schema: None,
    };
    check(&options, &current_dir).unwrap();
    Ok(())
}
