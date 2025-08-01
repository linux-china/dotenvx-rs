use crate::commands::linter::lint;
use crate::commands::list_env_files;
use clap::ArgMatches;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_file;
use std::env::current_dir;

pub fn doctor_command(_: &ArgMatches) {
    let current_dir = current_dir().unwrap();
    let env_files = list_env_files(current_dir, 1, &None);
    for env_file in env_files {
        let file_name = env_file.file_name().to_str().unwrap();
        let file_path = env_file.path();
        println!("Checking {file_name}:");
        let file_content = std::fs::read_to_string(file_path).unwrap();
        let public_key_line = file_content
            .lines()
            .find(|x| x.starts_with("DOTENV_PUBLIC_KEY"));
        if let Some(public_key_line) = public_key_line {
            let public_key_found = public_key_line.split('=').next().unwrap_or("").trim();
            let profile = get_profile_name_from_file(file_name);
            if let Some(profile_name) = profile {
                let public_key_name = format!("DOTENV_PUBLIC_KEY_{}", profile_name.to_uppercase());
                if public_key_found != public_key_name {
                    eprintln!("{}",
                         format!("Warning: The public key in {file_name} does not match the expected format: {public_key_name}").red()
                    );
                }
            } else if public_key_found != "DOTENV_PUBLIC_KEY" {
                eprintln!("{}",
                    format!("Warning: The public key in {file_name} does not match the expected format: DOTENV_PUBLIC_KEY").red()
                );
            }
        } else {
            eprintln!(
                "{}",
                format!("Warning: No public key found in {file_name}").red()
            );
        }
    }
    println!();
    println!("Run linter now...");
    lint().unwrap();
}
