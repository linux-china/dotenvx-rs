use crate::commands::crypt_util::{encrypt_env_item, EcKeyPair};
use crate::commands::decrypt::decrypt_env_entries;
use crate::commands::model::KeyPair;
use crate::commands::{
    construct_env_file_header, escape_shell_value, get_private_key_name_for_file, get_public_key_for_file,
    get_public_key_name_for_file, is_sensitive_key, write_key_pair, write_private_key_to_file,
    KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored_json::Paint;
use dotenvx_rs::common::get_profile_name_from_file;
use std::fs;
use std::path::{Path, PathBuf};

pub fn sync_command(command_matches: &ArgMatches) {
    let source = command_matches
        .get_one::<String>("source")
        .unwrap()
        .to_string();
    let target = command_matches
        .get_one::<String>("target")
        .unwrap()
        .to_string();
    let profile = get_profile_name_from_file(&target);
    let target_file_path = Path::new(&target);
    let source_file_exists = Path::new(&source).exists();
    if !source_file_exists {
        // create source file if it does not exist
        eprintln!("Source file '{source}' does not exist.");
        std::process::exit(1);
    }
    let target_file_exists = target_file_path.exists();
    if !target_file_exists {
        // create target env file if it does not exist
        let kp = EcKeyPair::generate();
        let new_public_key = kp.get_pk_hex();
        let source_file_content = fs::read_to_string(&source).unwrap();
        let entries = decrypt_env_entries(&source).unwrap();
        let mut new_lines: Vec<String> = Vec::new();
        let mut lines = source_file_content.lines().collect::<Vec<&str>>();
        let public_key_found = source_file_content.contains("DOTENV_PUBLIC_KEY");
        if public_key_found {
            if let Some(pos) = lines
                .iter()
                .position(|&x| x.starts_with("DOTENV_PUBLIC_KEY"))
            {
                lines = lines[pos + 1..].to_vec();
            }
        }
        for line in lines {
            if line.contains("=encrypted:") {
                let key = line.split('=').next().unwrap().trim();
                if let Some(value) = entries.get(key) {
                    let encrypted_value = encrypt_env_item(&new_public_key, value).unwrap();
                    new_lines.push(format!("{key}={encrypted_value}"));
                }
            } else {
                let key_name = line.split('=').next().unwrap().trim();
                if is_sensitive_key(key_name) && entries.contains_key(key_name) {
                    let value = entries.get(key_name).unwrap();
                    let encrypted_value = encrypt_env_item(&new_public_key, value).unwrap();
                    new_lines.push(format!("{key_name}={encrypted_value}"));
                } else {
                    if line.starts_with("# Environment variables") {
                        continue;
                    }
                    new_lines.push(line.to_string());
                }
            }
        }
        let header = construct_env_file_header(
            &get_public_key_name_for_file(&target),
            &new_public_key,
            &None,
            &None,
        );
        // write new env file
        let new_content = format!("{}\n{}", header.trim(), new_lines.join("\n").trim());
        fs::write(target_file_path, new_content.as_bytes()).unwrap();
        println!(
            "{}",
            format!("✔ target env file '{target}' created.").green()
        );
        // write key pair
        let mut key_pair = KeyPair::from(&new_public_key, &kp.get_sk_hex(), &None, &None, &profile);
        let absolute_path = fs::canonicalize(target_file_path).unwrap();
        key_pair.path = Some(absolute_path.to_string_lossy().to_string());
        if PathBuf::from(KEYS_FILE_NAME).exists() {
            // local .env.keys
            let private_key_name = get_private_key_name_for_file(&target);
            write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &key_pair).unwrap();
        } else {
            // global key store
            write_key_pair(&key_pair).unwrap();
            let private_key_short = &key_pair.private_key[0..6];
            println!(
                "{}",
                format!(
                    "✔ private key({private_key_short}) saved to $HOME/.dotenvx/.env.keys.json"
                )
                .green()
            );
        }
    } else {
        // update target env file
        let source_entries = decrypt_env_entries(&source).unwrap();
        let target_entries = decrypt_env_entries(&target).unwrap();
        let target_public_key = get_public_key_for_file(&target).unwrap_or("".to_string());
        // find absent keys in target
        let mut absent_variables: Vec<String> = Vec::new();
        for (key, value) in source_entries.iter() {
            if !key.starts_with("DOTENV_PUBLIC_KEY") && !target_entries.contains_key(key) {
                if !target_public_key.is_empty() && is_sensitive_key(key) {
                    let encrypted_value = encrypt_env_item(&target_public_key, value).unwrap();
                    absent_variables.push(format!("{key}={encrypted_value}"));
                } else {
                    absent_variables.push(format!("{}={}", key, escape_shell_value(value)));
                }
            }
        }
        if !absent_variables.is_empty() {
            let target_file_content = fs::read_to_string(&target).unwrap();
            let new_content = if target_file_content.ends_with('\n') {
                format!("{}{}", target_file_content, absent_variables.join("\n"))
            } else {
                format!("{}\n{}", target_file_content, absent_variables.join("\n"))
            };
            fs::write(target_file_path, new_content.as_bytes()).unwrap();
            println!(
                "{}",
                format!(
                    "✔ target env file '{target}' updated, added keys: {}",
                    absent_variables
                        .iter()
                        .map(|line| line.split('=').next().unwrap())
                        .collect::<Vec<&str>>()
                        .join(", ")
                )
                .green()
            );
        } else {
            println!("{}", format!("✔ no changes ({target})").green());
        }
    }
}
