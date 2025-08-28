use clap::ArgMatches;
use colored::Colorize;
use std::path::PathBuf;
use symlink::symlink_file;

pub fn link_command(command_matches: &ArgMatches, dotenvx_name: &str) {
    let command_name = command_matches
        .get_one::<String>("command")
        .map(|s| s.as_str())
        .unwrap();
    let target_path = PathBuf::from(command_name);
    if target_path.exists() {
        eprintln!("The target path already exists: {}", target_path.display());
        std::process::exit(1);
    }
    let dotenvx_path = if dotenvx_name.contains("/") || dotenvx_name.contains("\\") {
        PathBuf::from(dotenvx_name)
    } else {
        which::which(dotenvx_name).unwrap()
    };
    symlink_file(dotenvx_path, target_path).unwrap();
    println!(
        "{}",
        format!("${command_name} created and linked to dotenvx executable").green()
    );
}
