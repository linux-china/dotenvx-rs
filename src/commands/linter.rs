use clap::ArgMatches;
use dotenv_linter::cli::options::CheckOptions;
use dotenv_linter::{check, cli};

pub fn linter_command(_: &ArgMatches) {
    // Simulate command-line arguments
    let args_vec = vec![
        "dotenv-linter",
        "--skip",
        "UnorderedKey",
        "--exclude",
        ".env.keys",
    ];
    let current_dir = std::env::current_dir().unwrap();
    let matches = cli::command().try_get_matches_from(args_vec).unwrap();
    let options = CheckOptions::new(&matches);
    check(&options, &current_dir).unwrap();
}
