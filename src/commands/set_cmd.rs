use crate::commands::encrypt::encrypt_env_item;
use crate::commands::{
    create_env_file, get_env_file_arg, get_public_key_for_file, wrap_shell_value,
};
use clap::ArgMatches;
use lazy_static::lazy_static;
use regex::Regex;
use std::io::Read;
use std::path::Path;
use std::{fs, io};

lazy_static! {
    static ref REGEX_KEY_NAME: Regex = Regex::new(r"^[a-zA-Z_]+[a-zA-Z0-9_]*$").unwrap();
}

pub fn set_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let key_arg = command_matches.get_one::<String>("key").map(|s| s.as_str());
    let value_arg = command_matches
        .get_one::<String>("value")
        .map(|s| s.as_str());
    if key_arg.is_none() || value_arg.is_none() {
        eprintln!("Both key and value arguments are required.");
        return;
    }
    let key = key_arg.unwrap().replace('-', "_").to_uppercase();
    if !validate_key_name(&key) {
        eprintln!(
            "Invalid key name: '{key}'. Key names must start with a letter or underscore and can only contain letters, numbers, and underscores."
        );
        return;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    let mut value = value_arg.unwrap().to_string();
    // read from stdin if value is "-"
    if value == "-" {
        // Create a new String to store the piped input
        let mut input = String::new();
        // Read all data from stdin
        io::stdin()
            .read_to_string(&mut input)
            .expect("Failed to read from stdin");
        // Trim the input to remove any leading/trailing whitespace
        value = input.trim_end().to_string();
    }
    let env_file_exists = Path::new(&env_file).exists();
    // encrypt the value or not based on the existing .env file content
    let mut encrypt_mode = true;
    let mut env_file_content = String::new();
    if env_file_exists {
        if let Ok(file_content) = fs::read_to_string(&env_file) {
            env_file_content = file_content;
        }
        encrypt_mode = env_file_content.contains("=encrypted:");
    }
    // if encrypt or plain arg is provided, we override the encrypt_mode
    if command_matches.get_flag("plain") {
        encrypt_mode = false;
    }
    if command_matches.get_flag("encrypt") {
        encrypt_mode = true;
    }
    let public_key = get_public_key_for_file(&env_file).unwrap();
    let pair = if encrypt_mode {
        let encrypted_value = encrypt_env_item(&public_key, &value).unwrap();
        format!("{key}={encrypted_value}")
    } else {
        format!("{}={}", key, wrap_shell_value(&value))
    };
    if command_matches.get_flag("stdout") {
        println!("export {pair}");
        return;
    }
    if !env_file_exists {
        create_env_file(&env_file, &public_key, Some(&pair));
        println!("Added {key} to {env_file}");
    } else if env_file_content.contains(&format!("{key}=")) {
        // Update existing key
        let new_content = env_file_content
            .lines()
            .map(|line| {
                if line.starts_with(&key) {
                    pair.clone()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        fs::write(&env_file, new_content).expect("Failed to write to the .env file");
        println!("Updated {key} in {env_file}");
    } else {
        // Add new key
        let mut new_content = env_file_content;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&pair);
        fs::write(&env_file, new_content).expect("Failed to write to the .env file");
        println!("Added {key} to {env_file}");
    }
}

pub fn validate_key_name(key: &str) -> bool {
    REGEX_KEY_NAME.is_match(key)
}

#[cfg(test)]
mod tests {
    use crate::commands::set_cmd::validate_key_name;

    #[test]
    fn test_validate_key_name() {
        let valid_keys = vec!["KEY", "NO-WORK", "KEY_NAME", "KEY_NAME_123"];
        for valid_key in valid_keys {
            let result = validate_key_name(valid_key);
            println!("{valid_key}: {result}");
        }
    }
}
