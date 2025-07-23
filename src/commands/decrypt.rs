use crate::commands::get_env_file_arg;
use base64::engine::general_purpose;
use base64::Engine;
use clap::ArgMatches;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_file;
use std::collections::HashMap;
use std::fs;

pub fn decrypt_command(command_matches: &ArgMatches) {
    let env_file = get_env_file_arg(command_matches);
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !env_file_path.exists() {
        eprintln!(
            "Error: The specified env file '{}' does not exist.",
            env_file
        );
        return;
    }
    let mut is_changed = false;
    let entries = decrypt_env_entries(&env_file).unwrap();
    let file_content = fs::read_to_string(&env_file_path).unwrap();
    let mut new_lines: Vec<String> = Vec::new();
    for line in file_content.lines() {
        if line.contains("=encrypted:") {
            let key = line.split('=').next().unwrap().trim();
            if let Some(value) = entries.get(key) {
                // todo value escape
                let new_value = value.replace("\n", "\\n");
                new_lines.push(format!("{}={}", key, new_value));
                is_changed = true;
            }
        } else {
            new_lines.push(line.to_string());
        }
    }
    if !is_changed {
        println!("{}", format!("✔ no changes ({})", env_file).green());
    } else {
        let new_file_content = new_lines.join("\n");
        fs::write(&env_file_path, new_file_content.as_bytes()).unwrap();
        println!("{}", format!("✔ decrypted ({})", env_file).green());
    }
}

pub fn decrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    let private_key = crate::commands::get_private_key(&profile_name)?;
    let mut entries: HashMap<String, String> = HashMap::new();
    for item in dotenvy::from_filename_iter(env_file)? {
        let (key, value) = &item.unwrap();
        if value.starts_with("encrypted:") {
            let decrypted_text = decrypt_env_item(&private_key, value)?;
            entries.insert(key.clone(), decrypted_text);
        } else {
            entries.insert(key.clone(), value.clone());
        }
    }
    Ok(entries)
}

fn decrypt_env_item(
    private_key: &str,
    encrypted_text: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = if encrypted_text.starts_with("encrypted:") {
        general_purpose::STANDARD
            .decode(&encrypted_text[10..])
            .unwrap()
    } else {
        general_purpose::STANDARD.decode(encrypted_text).unwrap()
    };
    let sk = hex::decode(private_key).unwrap();
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes).unwrap();
    Ok(String::from_utf8(decrypted_bytes)?)
}
#[cfg(test)]
mod tests {
    #[test]
    fn test_decrypt_dotenv() {
        let entries = super::decrypt_env_entries(".env").unwrap();
        println!("{:?}", entries);
    }
}
