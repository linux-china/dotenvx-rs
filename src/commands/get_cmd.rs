use crate::commands::crypt_util::{decrypt_env_item, generate_totp_password};
use crate::commands::{
    adjust_env_key, get_env_file_arg, get_private_key_for_file, read_dotenv_file, std_output,
};
use clap::ArgMatches;
use std::collections::HashMap;

pub fn get_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let key_arg = command_matches.get_one::<String>("key").map(|s| s.as_str());
    let env_file = get_env_file_arg(command_matches, profile);
    let default_format = "text".to_owned();
    let format = command_matches
        .get_one::<String>("format")
        .unwrap_or(&default_format);
    let is_env_override = true ; // command_matches.get_flag("override");
    // if a key is provided, we read the .env file and print the value of the key
    let mut decrypted_entries: HashMap<String, String> = HashMap::new();
    if let Some(key_name) = key_arg {
        let key_name = adjust_env_key(key_name, &env_file);
        let private_key = get_private_key_for_file(&env_file).unwrap();
        // get the decrypted value from the command line arguments if provided
        let plain_value = if let Some(value) = command_matches.get_one::<String>("value") {
            decrypt_env_item(&private_key, value).unwrap_or(value.clone())
        } else {
            // get key's value from the .env file
            if let Ok(entries) = read_dotenv_file(&env_file)
                && let Some(value) = entries.get(&key_name)
            {
                if value.starts_with("encrypted:") {
                    decrypt_env_item(&private_key, value).unwrap_or(value.clone())
                } else {
                    value.clone()
                }
            } else {
                "".to_string()
            }
        };
        if format == "text" && plain_value.is_empty() {
            eprintln!("Key '{key_name}' not found in {env_file}");
            std::process::exit(1);
        }

        if !is_env_override && let Ok(env_plain_value) = std::env::var(key_name.clone()) {
            decrypted_entries.insert(key_name.clone(), env_plain_value.clone());
        } else {
            decrypted_entries.insert(key_name.clone(), plain_value.clone());
        }
        if plain_value.starts_with("otpauth://totp") {
            let otp_password = generate_totp_password(&plain_value).unwrap_or_default();
            let totp_password_key = format!("{key_name}_PASSWORD");
            decrypted_entries.insert(totp_password_key, otp_password);
        }
    }
    std_output(&decrypted_entries, &Some(format));
}
