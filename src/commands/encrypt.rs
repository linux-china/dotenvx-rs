use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::{
    construct_env_file_header, get_env_file_arg, get_public_key_for_file, get_public_key_name,
    write_public_key_to_file,
};
use clap::ArgMatches;
use colored::Colorize;
use std::collections::HashMap;
use std::fs;

pub fn encrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let is_stdout = command_matches.get_flag("stdout");
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !env_file_path.exists() {
        // create default env file if it does not exist
        let public_key = get_public_key_for_file(&env_file).unwrap();
        println!("'{env_file}' does not exist, creating a new file with public key.");
        write_public_key_to_file(&env_file_path, &public_key).unwrap();
        return;
    }
    let mut is_changed = false;
    let file_content = fs::read_to_string(&env_file_path).unwrap();
    let entries = encrypt_env_entries(&env_file).unwrap();
    let mut new_lines: Vec<String> = Vec::new();
    for line in file_content.lines() {
        if line.starts_with("#") {
            // comment lines
            new_lines.push(line.to_string());
        } else if line.is_empty() {
            // empty lines
            new_lines.push(line.to_string());
        } else if line.starts_with("DOTENV_PUBLIC_KEY") {
            // public key line
            new_lines.push(line.to_string());
        } else if line.contains("=encrypted:") {
            // already encrypted lines
            new_lines.push(line.to_string());
        } else if line.contains('=') {
            // key-value pairs
            let key = line.split('=').next().unwrap().trim();
            if let Some(value) = entries.get(key) {
                new_lines.push(format!("{key}={value}"));
                is_changed = true;
            }
        }
    }
    if is_stdout {
        for line in new_lines {
            println!("{line}");
        }
        return;
    }
    if !is_changed {
        println!("{}", format!("✔ no changes ({env_file})").green());
    } else {
        let new_file_content = if file_content.contains("DOTENV_PUBLIC_KEY") {
            new_lines.join("\n")
        } else {
            // append public key to .env file if it does not exist
            let public_key_name = get_public_key_name(profile);
            let public_key = get_public_key_for_file(&env_file).unwrap();
            construct_env_file_header(&public_key_name, &public_key) + &new_lines.join("\n")
        };
        fs::write(&env_file_path, new_file_content.as_bytes()).unwrap();
        println!("{}", format!("✔ encrypted ({env_file})").green());
    }
}

pub fn encrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let public_key = get_public_key_for_file(env_file)?;
    let mut entries: HashMap<String, String> = HashMap::new();
    for item in dotenvy::from_filename_iter(env_file)? {
        let (key, value) = &item.unwrap();
        if !value.starts_with("encrypted:") {
            let encrypted_text = encrypt_env_item(&public_key, value)?;
            entries.insert(key.clone(), encrypted_text);
        } else {
            entries.insert(key.clone(), value.clone());
        }
    }
    Ok(entries)
}
