use crate::commands::crypt_util::{decrypt_env_item, generate_totp_password};
use crate::commands::decrypt::decrypt_env_entries;
use crate::commands::{
    adjust_env_key, get_env_file_arg, get_private_key_for_file, merge_with_environment_variables,
    read_dotenv_file, escape_shell_value,
};
use clap::ArgMatches;
use colored_json::{to_colored_json_auto, ToColoredJson};

pub fn get_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let key_arg = command_matches.get_one::<String>("key").map(|s| s.as_str());
    let env_file = get_env_file_arg(command_matches, profile);
    let format = if let Some(arg_value) = command_matches.get_one::<String>("format") {
        arg_value.clone()
    } else {
        "json".to_owned()
    };
    let is_env_override = command_matches.get_flag("override");
    // if a key is provided, we read the .env file and print the value of the key
    if let Some(key_name) = key_arg {
        let key_name = adjust_env_key(key_name, &env_file);
        let private_key = get_private_key_for_file(&env_file).unwrap();
        // get the decrypted value from the command line arguments if provided
        if let Some(value) = command_matches.get_one::<String>("value") {
            let plain_value = decrypt_env_item(&private_key, value).unwrap_or(value.clone());
            if format == "shell" {
                println!("export {}={}", key_name, escape_shell_value(&plain_value));
            } else {
                println!("{plain_value}");
            }
            return;
        }
        if let Ok(entries) = read_dotenv_file(&env_file) {
            if let Some(value) = entries.get(&key_name) {
                let plain_value = if value.starts_with("encrypted:") {
                    decrypt_env_item(&private_key, value).unwrap_or(value.clone())
                } else {
                    value.clone()
                };
                if format == "shell" {
                    println!("export {}={}", key_name, escape_shell_value(&plain_value));
                    if key_name.starts_with("otpauth://totp") {
                        let otp_password = generate_totp_password(&plain_value).unwrap_or_default();
                        let totp_password_key = format!("{key_name}_PASSWORD");
                        println!("export {totp_password_key}={otp_password}");
                    }
                } else if format == "json" {
                    let body = if key_name.starts_with("otpauth://totp") {
                        let totp_password_key = format!("{key_name}_PASSWORD");
                        let totp_password =
                            generate_totp_password(&plain_value).unwrap_or_default();
                        serde_json::json!({key_name: plain_value,totp_password_key:totp_password})
                    } else {
                        serde_json::json!({key_name: plain_value})
                    };
                    println!("{}", to_colored_json_auto(&body).unwrap());
                } else {
                    println!("{plain_value}");
                }
            } else {
                eprintln!("Key '{key_name}' not found in {env_file}");
            }
        } else {
            eprintln!("Failed to read the .env file: {env_file}");
        }
    } else {
        // print all entries with json format
        if let Ok(mut entries) = decrypt_env_entries(&env_file) {
            merge_with_environment_variables(&mut entries, is_env_override);
            if format == "shell" {
                for (key, value) in &entries {
                    println!("export {}={}", key, escape_shell_value(value));
                }
            } else {
                let body = serde_json::json!(entries);
                println!("{}", to_colored_json_auto(&body).unwrap());
            }
        } else {
            eprintln!("Failed to decrypt the .env file: {env_file}");
        }
    }
}
