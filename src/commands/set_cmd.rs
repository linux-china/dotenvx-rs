use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::framework::detect_framework;
use crate::commands::{
    adjust_env_key, create_env_file, escape_shell_value, get_env_file_arg, get_public_key_for_file,
    is_sensitive_key, update_env_file,
};
use arboard::Clipboard;
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
    let mut env_file = get_env_file_arg(command_matches, profile);
    let mut key_arg = command_matches
        .get_one::<String>("key")
        .map(|s| s.to_string());
    let mut key_value: Option<String> = None;
    if key_arg.is_none() {
        // read key and value from prompt
        println!("Please provide the key and value to set.");
        key_arg = rprompt::prompt_reply("Key: ").ok();
        let value = rpassword::prompt_password("Value: ").unwrap();
        if value.is_empty() {
            eprintln!("Error: Value cannot be empty, please provide a value.");
            return;
        }
        key_value = Some(value);
    } else {
        let value_arg = command_matches
            .get_one::<String>("value")
            .map(|s| s.as_str());
        let mut value = value_arg.unwrap_or_default().to_string();
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
            if value.is_empty() {
                eprintln!("Error: value cannot be empty when reading from stdin.");
                return;
            }
        } else if command_matches.get_flag("clipboard") {
            if let Ok(mut clipboard) = Clipboard::new() {
                if let Ok(clipboard_text) = clipboard.get_text() {
                    value = clipboard_text.trim().to_string();
                    clipboard.clear().unwrap();
                } else {
                    eprintln!("Failed to read from clipboard.");
                    std::process::exit(1);
                }
            }
        }
        if value.is_empty() {
            eprintln!("Error: Value cannot be empty, please provide a value.");
            return;
        }
        key_value = Some(value);
    }
    let key = adjust_env_key(&key_arg.unwrap(), &env_file);
    if !validate_key_name(&key, &env_file) {
        eprintln!(
            "Invalid key name: '{key}'. Key names must start with a letter or underscore and can only contain letters, numbers, and underscores."
        );
        return;
    }
    let value = key_value.unwrap();
    let env_file_exists = Path::new(&env_file).exists();
    // encrypt the value or not based on the existing .env file content
    let mut encrypt_mode = is_sensitive_key(&key);
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
        format!("{}={}", key, escape_shell_value(&value))
    };
    let pair = adjust_pair_for_file(&env_file, pair);
    if command_matches.get_flag("stdout") {
        println!("export {pair}");
        return;
    }
    if !env_file_exists {
        // create .env file if it does not exist
        if let Some(framework) = detect_framework()
            && framework == "gofr"
            && env_file.starts_with(".env")
        {
            env_file = format!("configs/{env_file}");
        }
        create_env_file(&env_file, &public_key, Some(&pair), &None, &None);
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
        update_env_file(&env_file, &public_key, &new_content);
        println!("Updated {key} in {env_file}");
    } else {
        // Add new key
        let mut new_content = env_file_content;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&pair);
        update_env_file(&env_file, &public_key, &new_content);
        println!("Added {key} to {env_file}");
    }
}

pub fn validate_key_name(key: &str, env_file: &str) -> bool {
    if env_file.contains(".env") {
        REGEX_KEY_NAME.is_match(key)
    } else {
        true
    }
}

fn adjust_pair_for_file(env_file: &str, pair: String) -> String {
    if env_file.ends_with(".xml") {
        format!("<!-- {pair} -->")
    } else if env_file.ends_with(".sh") || env_file.ends_with(".toml") {
        format!("# {pair}")
    } else {
        pair
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::set_cmd::validate_key_name;

    #[test]
    fn test_validate_key_name() {
        let valid_keys = vec!["KEY", "NO-WORK", "KEY_NAME", "KEY_NAME_123"];
        for valid_key in valid_keys {
            let result = validate_key_name(valid_key, ".env");
            println!("{valid_key}: {result}");
        }
    }
}
