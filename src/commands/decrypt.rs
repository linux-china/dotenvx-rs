use crate::commands::crypt_util::{decrypt_env_item, decrypt_value};
use crate::commands::{
    adjust_env_key, escape_shell_value, get_env_file_arg, get_private_key_for_file,
    is_remote_env_file, read_content_from_dotenv_url, read_dotenv_url, std_output,
};
use clap::ArgMatches;
use colored::Colorize;
use glob::Pattern;
use java_properties::PropertiesIter;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;

pub fn decrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    if let Some(arg_value) = command_matches.get_one::<String>("value") {
        decrypt_value(profile, arg_value);
        return;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    let is_remote_env = is_remote_env_file(&env_file);
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !is_remote_env && !std::path::PathBuf::from(&env_file).exists() {
        eprintln!("Error: The specified env file '{env_file}' does not exist.");
        return;
    }
    let env_keys = command_matches.get_many::<String>("keys");
    let mut entries = decrypt_env_entries(&env_file).unwrap();
    let mut hint = format!(".env file({env_file})");
    if let Some(keys) = env_keys {
        let patterns: Vec<Pattern> = keys
            .map(|x| adjust_env_key(x, &env_file))
            .map(|x| Pattern::new(&x).unwrap())
            .collect();
        entries.retain(|key, _| patterns.iter().any(|pattern| pattern.matches(key)));
        hint = format!("keys in .env file: {env_file}");
    }
    let is_stdout = command_matches.get_flag("stdout");
    // stdout with format shell, json or csv
    if is_stdout
        && let Some(fmt) = command_matches.get_one::<String>("format")
        && fmt != "text"
    {
        std_output(&entries, &Some(fmt));
        if fmt == "shell" {
            println!("# Run this command to configure your shell:");
            println!("# eval $(dotenvx decrypt -f {env_file} --stdout --format shell)");
        }
        return;
    }
    let file_content = if is_remote_env {
        read_content_from_dotenv_url(&env_file, None).unwrap()
    } else {
        fs::read_to_string(&env_file_path).unwrap()
    };
    let mut new_lines: Vec<String> = Vec::new();
    let mut is_changed = false;
    for line in file_content.lines() {
        if line.contains("=encrypted:") {
            let key = line.split('=').next().unwrap().trim();
            if let Some(value) = entries.get(key) {
                let new_value = escape_shell_value(value);
                new_lines.push(format!("{key}={new_value}"));
                is_changed = true;
            } else {
                // If the key is not in the entries, we keep the original line
                new_lines.push(line.to_string());
            }
        } else {
            new_lines.push(line.to_string());
        }
    }
    // stdout with text format
    if is_stdout {
        for line in new_lines {
            println!("{line}");
        }
        return;
    }
    if !is_changed {
        println!("{}", format!("✔ no changes ({env_file})").green());
    } else {
        let new_file_content = new_lines.join("\n");
        fs::write(&env_file_path, new_file_content.as_bytes()).unwrap();
        println!("{}", format!("✔ {hint} decrypted ({env_file})").green());
    }
}

pub fn decrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let private_key = get_private_key_for_file(env_file)?;
    let mut entries: HashMap<String, String> = HashMap::new();
    if env_file.ends_with(".properties") {
        let f = File::open(env_file)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader)
            .read_into(|key, value| {
                if value.starts_with("encrypted:") {
                    let decrypted_text = decrypt_env_item(&private_key, &value).unwrap();
                    entries.insert(key.clone(), decrypted_text);
                } else {
                    entries.insert(key.clone(), value.clone());
                }
            })
            .unwrap();
    } else {
        let items = if env_file.starts_with("http://") || env_file.starts_with("https://") {
            read_dotenv_url(env_file, None)?
        } else {
            let mut entries: HashMap<String, String> = HashMap::new();
            for item in dotenvy::from_filename_iter(env_file)? {
                let (key, value) = &item.unwrap();
                entries.insert(key.clone(), value.clone());
            }
            entries
        };
        for (key, value) in items {
            if value.starts_with("encrypted:") {
                let decrypted_text = decrypt_env_item(&private_key, &value)?;
                entries.insert(key.clone(), decrypted_text);
            } else {
                entries.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_decrypt_dotenv() {
        let entries = super::decrypt_env_entries(".env").unwrap();
        println!("{entries:?}");
    }
}
