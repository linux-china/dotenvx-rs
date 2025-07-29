use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::model::{sign_and_update_env_file_content, sign_available};
use crate::commands::{
    adjust_env_key, construct_env_file_header, get_env_file_arg, get_private_key,
    get_public_key_for_file, get_public_key_name, update_env_file, write_public_key_to_file,
};
use clap::ArgMatches;
use colored_json::Paint;
use glob::Pattern;
use java_properties::PropertiesIter;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;

pub fn encrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let env_keys = command_matches.get_many::<String>("keys");
    let is_stdout = command_matches.get_flag("stdout");
    let is_sign_required = command_matches.get_flag("sign");
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
    let mut entries = encrypt_env_entries(&env_file).unwrap();
    let mut hint = format!(".env file({env_file})");
    if let Some(keys) = env_keys {
        let patterns: Vec<Pattern> = keys
            .map(|x| adjust_env_key(x, &env_file))
            .map(|x| Pattern::new(&x).unwrap())
            .collect();
        entries.retain(|key, _| patterns.iter().any(|pattern| pattern.matches(key)));
        hint = format!("keys in .env file: {env_file}");
    }
    let mut new_lines: Vec<String> = Vec::new();
    for line in file_content.lines() {
        if line.starts_with("#") {
            // comment lines
            new_lines.push(line.to_string());
        } else if line.is_empty() {
            // empty lines
            new_lines.push(line.to_string());
        } else if line.starts_with("DOTENV_PUBLIC_KEY") || line.starts_with("dotenv.public.key") {
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
            } else {
                // if the key is not in the entries, we keep the original line
                new_lines.push(line.to_string());
            }
        }
    }
    if is_stdout {
        let new_content = new_lines.join("\n");
        if is_sign_required {
            println!(
                "{}",
                add_or_replace_signature(profile, &new_content).unwrap()
            );
        } else {
            println!("{new_content}");
        }
        return;
    }
    if !is_changed {
        if sign_available(&file_content) {
            println!("{}", format!("✔ no changes ({env_file})").green());
        } else {
            let new_content = add_or_replace_signature(profile, &file_content).unwrap();
            fs::write(&env_file_path, new_content.as_bytes()).unwrap();
            println!("{}", format!("✔ sign added for ({env_file})").green());
        }
    } else {
        let public_key = get_public_key_for_file(&env_file).unwrap();
        let mut new_file_content = if file_content.contains("DOTENV_PUBLIC_KEY=")
            || file_content.contains("dotenv.public.key=")
        {
            new_lines.join("\n")
        } else {
            // append public key to .env file if it does not exist
            let public_key_name = get_public_key_name(profile);
            construct_env_file_header(&public_key_name, &public_key) + &new_lines.join("\n")
        };
        if is_sign_required {
            new_file_content = add_or_replace_signature(profile, &new_file_content).unwrap();
        }
        update_env_file(&env_file, &public_key, &new_file_content);
        if is_sign_required {
            println!(
                "{}",
                format!("✔ {hint} encrypted and signed ({env_file})").green()
            );
        } else {
            println!("{}", format!("✔ {hint} encrypted ({env_file})").green());
        }
    }
}

pub fn add_or_replace_signature(
    profile: &Option<String>,
    env_file_content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key = get_private_key(profile).unwrap();
    sign_and_update_env_file_content(&private_key, env_file_content)
}

pub fn encrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let public_key = get_public_key_for_file(env_file)?;
    let mut entries: HashMap<String, String> = HashMap::new();
    if env_file.ends_with(".properties") {
        let f = File::open(env_file)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader)
            .read_into(|key, value| {
                if !value.starts_with("encrypted:") {
                    let encrypted_text = encrypt_env_item(&public_key, &value).unwrap();
                    entries.insert(key, encrypted_text);
                } else {
                    entries.insert(key, value);
                }
            })
            .unwrap();
    } else {
        for item in dotenvy::from_filename_iter(env_file)? {
            let (key, value) = &item.unwrap();
            if !value.starts_with("encrypted:") {
                let encrypted_text = encrypt_env_item(&public_key, value)?;
                entries.insert(key.clone(), encrypted_text);
            } else {
                entries.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(entries)
}
