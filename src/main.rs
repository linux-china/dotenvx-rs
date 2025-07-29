use crate::clap_app::build_dotenvx_app;
use crate::commands::crypt_util::{decrypt_file, encrypt_file};
use crate::commands::decrypt::decrypt_command;
use crate::commands::diff::diff_command;
use crate::commands::encrypt::encrypt_command;
use crate::commands::get_cmd::get_command;
use crate::commands::init::init_command;
use crate::commands::keypair::keypair_command;
use crate::commands::list::ls_command;
use crate::commands::rotate::rotate_command;
use crate::commands::run::{run_command, run_command_line};
use crate::commands::set_cmd::set_command;
use crate::commands::verify::verify_command;
use clap::ArgMatches;
use dotenvx_rs::common::get_profile_name_from_env;
use std::env;

mod clap_app;
pub mod commands;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = build_dotenvx_app();
    let mut raw_args: Vec<String> = env::args().collect();
    let sub_command_index = raw_args.iter().position(|arg| arg == "--").unwrap_or(0);
    // check if the run sub-command is present
    if sub_command_index > 0 && raw_args[1] == "run" {
        let dotenvx_args = raw_args[0..sub_command_index]
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>();
        let matches = app.try_get_matches_from(dotenvx_args).unwrap();
        let command_matches = matches.subcommand_matches("run").unwrap();
        let profile = get_profile(&matches);
        let exit_code = run_command(
            &raw_args[sub_command_index + 1..],
            command_matches,
            &profile,
        );
        std::process::exit(exit_code);
    }
    // check "-pp" for decryption to be compatible with python-dotenvx
    if raw_args.contains(&"-pp".to_string()) {
        // remove "-pp" from the arguments
        raw_args.retain(|arg| arg != "-pp");
        raw_args.push("--pretty-print".to_owned());
        let matches = app.try_get_matches_from(raw_args).unwrap();
        let command_matches = matches.subcommand_matches("get").unwrap();
        let profile = get_profile(&matches);
        get_command(command_matches, &profile);
        return Ok(());
    }
    let matches = app.get_matches();
    // check no-color flag
    if matches.get_flag("no-color") {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }
    // seal/unseal $HOME/.env.keys file
    if matches.get_flag("seal") {
        encrypt_env_keys_file();
        return Ok(());
    } else if matches.get_flag("unseal") {
        decrypt_env_keys_file();
        return Ok(());
    }
    // check if the --profile flag is set
    let profile = get_profile(&matches);
    // check -c and run the command
    if matches.get_one::<String>("command").is_some() {
        let exit_code = run_command_line(&matches, &profile);
        std::process::exit(exit_code);
    }
    // run the sub-commands
    if let Some((command, command_matches)) = matches.subcommand() {
        match command {
            "init" => init_command(command_matches, &profile),
            "encrypt" => encrypt_command(command_matches, &profile),
            "decrypt" => decrypt_command(command_matches, &profile),
            "keypair" => keypair_command(command_matches, &profile),
            "ls" => ls_command(command_matches, &profile),
            "get" => get_command(command_matches, &profile),
            "set" => set_command(command_matches, &profile),
            "diff" => diff_command(command_matches),
            "rotate" => rotate_command(command_matches, &profile),
            "verify" => verify_command(command_matches, &profile),
            &_ => println!("Unknown command"),
        }
    }
    Ok(())
}

fn encrypt_env_keys_file() {
    let password = rpassword::prompt_password("Your password: ").unwrap();
    let password_confirm = rpassword::prompt_password("Password again: ").unwrap();
    if password != password_confirm {
        eprintln!("Passwords do not match. Please try again.");
        return;
    }
    let home_dir = dirs::home_dir().unwrap();
    if home_dir.join(".env.keys").exists() {
        let keys_file_path = home_dir.join(".env.keys");
        let encrypted_file_path = home_dir.join(".env.keys.aes");
        if encrypt_file(&keys_file_path, &encrypted_file_path, &password).is_ok() {
            std::fs::remove_file(&keys_file_path).unwrap();
            println!("✔ Successfully encrypted the $HOME/.env.keys file to .env.keys.aes",);
        } else {
            eprintln!(
                "Failed to encrypt the .env.keys file. Please check your password and try again."
            );
        }
    } else {
        eprintln!("$HOME/.env.keys file does not exist.");
    }
}

fn decrypt_env_keys_file() {
    let password = rpassword::prompt_password("Your password: ").unwrap();
    let home_dir = dirs::home_dir().unwrap();
    if home_dir.join(".env.keys.aes").exists() {
        let keys_file_path = home_dir.join(".env.keys");
        let encrypted_file_path = home_dir.join(".env.keys.aes");
        if decrypt_file(&encrypted_file_path, &keys_file_path, &password).is_ok() {
            println!("✔ Successfully decrypted the .env.keys.aes file to $HOME/.env.keys",);
        } else {
            eprintln!(
                "Failed to decrypt the $HOME/.env.keys.aes file. Please check your password and try again."
            );
        }
    } else {
        eprintln!("$HOME/.env.keys.aes file does not exist.");
    }
}

fn get_profile(global_matches: &ArgMatches) -> Option<String> {
    let profile = global_matches
        .get_one::<String>("profile")
        .map(|s| s.to_owned());
    // If profile is not set, try to read from environment variables
    if profile.is_none() {
        return get_profile_name_from_env();
    }
    profile
}
