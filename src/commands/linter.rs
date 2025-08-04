use clap::ArgMatches;

pub fn linter_command(_: &ArgMatches) {
    lint().unwrap();
}

pub fn lint() -> anyhow::Result<()> {
    // use dotenv_linter::cli::options::CheckOptions;
    // use dotenv_linter::{check, cli};
    // let args_vec = vec![
    //     "dotenv-linter",
    //     "--skip",
    //     "UnorderedKey",
    //     "--exclude",
    //     ".env.keys",
    // ];
    // let current_dir = std::env::current_dir()?;
    // let matches = cli::command().try_get_matches_from(args_vec)?;
    // let options = CheckOptions::new(&matches);
    // check(&options, &current_dir).unwrap();
    Ok(())
}
