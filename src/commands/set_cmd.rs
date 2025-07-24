use crate::commands::encrypt::encrypt_env_item;
use crate::commands::{
    create_env_file, get_env_file_arg, get_public_key_for_file, wrap_shell_value,
};
use clap::ArgMatches;
use std::io::Read;
use std::path::Path;
use std::{fs, io};

pub fn set_command(command_matches: &ArgMatches) {
    let key_arg = command_matches.get_one::<String>("key").map(|s| s.as_str());
    let value_arg = command_matches
        .get_one::<String>("value")
        .map(|s| s.as_str());
    if key_arg.is_none() || value_arg.is_none() {
        eprintln!("Both key and value arguments are required.");
        return;
    }
    let env_file = get_env_file_arg(command_matches);
    let key = key_arg.unwrap().to_uppercase();
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
        value = input.trim().to_string();
    }
    let env_file_exists = Path::new(&env_file).exists();
    let mut encrypt_mode = true;
    let mut env_file_content = String::new();
    if env_file_exists {
        if let Ok(file_content) = fs::read_to_string(&env_file) {
            env_file_content = file_content;
        }
        encrypt_mode = env_file_content.contains("=encrypted:");
    }
    let public_key = get_public_key_for_file(&env_file).unwrap();
    let pair = if encrypt_mode {
        let encrypted_value = encrypt_env_item(&public_key, &value).unwrap();
        format!("{}={}", key, encrypted_value)
    } else {
        format!("{}={}", key, wrap_shell_value(&value))
    };
    if command_matches.get_flag("stdout") {
        print!("export {}", pair);
        return;
    }
    if !env_file_exists {
        create_env_file(&env_file, &public_key, Some(&pair));
        println!("Added {} to {}", key, env_file);
    } else {
        if env_file_content.contains(&format!("{}=", key)) {
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
            println!("Updated {} in {}", key, env_file);
        } else {
            // Add new key
            let mut new_content = env_file_content;
            if !new_content.is_empty() && !new_content.ends_with('\n') {
                new_content.push('\n');
            }
            new_content.push_str(&pair);
            fs::write(&env_file, new_content).expect("Failed to write to the .env file");
            println!("Added {} to {}", key, env_file);
        }
    }
}
