use crate::commands::crypt_util::verify_signature;
use crate::commands::model::{get_signature, remove_signature};
use crate::commands::{get_env_file_arg, get_public_key_name, read_dotenv_file};
use clap::ArgMatches;
use colored_json::Paint;

pub fn verify_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let env_file_path = std::path::PathBuf::from(&env_file);
    if let Ok(file_content) = std::fs::read_to_string(&env_file_path) {
        if !file_content.contains("DOTENV_PUBLIC_KEY") {
            eprintln!("The .env file does not contain a public key: {env_file}");
            std::process::exit(1);
        }
        if let Some(signature) = get_signature(&file_content) {
            let public_key_name = get_public_key_name(profile);
            let entries = read_dotenv_file(env_file_path).unwrap();
            if let Some(public_key) = entries.get(&public_key_name) {
                let message = remove_signature(&file_content);
                if let Ok(is_valid) = verify_signature(public_key, &message, &signature) {
                    if is_valid {
                        println!(
                            "{}",
                            format!("✔ The .env file ({env_file}) is valid.").green()
                        );
                    } else {
                        eprintln!(
                            "{}",
                            format!("The .env file ({env_file}) signature is invalid. BE CAREFUL to use it.")
                                .red(),
                        );
                        std::process::exit(1);
                    }
                } else {
                    eprintln!(
                        "{}",
                        format!(
                            "The .env file ({env_file}) signature is invalid. BE CAREFUL to use it."
                        )
                        .red(),
                    );
                    std::process::exit(1);
                }
            } else {
                eprintln!("Could not retrieve the public key from .env.file ({env_file})");
                std::process::exit(1);
            }
        } else {
            eprintln!("The .env file({env_file}) does not contain a valid signature.");
            std::process::exit(1);
        }
    } else {
        eprintln!("The specified .env file does not exist: {env_file}");
        std::process::exit(1);
    }
}
