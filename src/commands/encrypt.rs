use crate::commands::get_profile_name;
use base64::engine::general_purpose;
use base64::Engine;
use clap::ArgMatches;
use colored::Colorize;
use std::collections::HashMap;
use std::fs;

pub fn encrypt_command(command_matches: &ArgMatches) {
    let env_file = if let Some(arg_value) = command_matches.get_one::<String>("env-file") {
        arg_value.clone()
    } else {
        ".env".to_string()
    };
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !env_file_path.exists() {
        eprintln!(
            "Error: The specified env file '{}' does not exist.",
            env_file
        );
        return;
    }
    let entries = encrypt_env_entries(&env_file).unwrap();
    let file_content = fs::read_to_string(&env_file_path).unwrap();
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
                new_lines.push(format!("{}={}", key, value));
            }
        }
    }
    let new_file_content = new_lines.join("\n");
    fs::write(&env_file_path, new_file_content.as_bytes()).unwrap();
    println!("{}", format!("✔ encrypted ({})", env_file).green());
}

pub fn encrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name(env_file);
    let public_key = crate::commands::get_public_key(&profile_name)?;
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

fn encrypt_env_item(
    public_key: &str,
    value_plain: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let pk_bytes = hex::decode(public_key).unwrap();
    let encrypted_bytes = ecies::encrypt(&pk_bytes, value_plain.as_bytes()).unwrap();
    let base64_text = general_purpose::STANDARD.encode(encrypted_bytes);
    Ok(format!("encrypted:{}", base64_text))
}
