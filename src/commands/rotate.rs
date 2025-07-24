use crate::commands::decrypt::decrypt_env_entries;
use crate::commands::encrypt::encrypt_env_entries;
use crate::commands::{
    get_env_file_arg, get_private_key_name_for_file, wrap_shell_value, write_private_key_to_file, write_public_key_to_file,
    EcKeyPair, KEYS_FILE_NAME,
};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

pub fn rotate_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    if Path::new(&env_file).exists() {
        let entries = decrypt_env_entries(&env_file).unwrap();
        let file_content = fs::read_to_string(&env_file).unwrap();
        let encrypt_mode = file_content.contains("=encrypted:");
        let mut plain_lines: Vec<String> = Vec::new();
        for line in file_content.lines() {
            if line.contains("=encrypted:") {
                let key = line.split('=').next().unwrap().trim();
                if let Some(value) = entries.get(key) {
                    let new_value = wrap_shell_value(value);
                    plain_lines.push(format!("{}={}", key, new_value));
                }
            } else {
                plain_lines.push(line.to_string());
            }
        }
        // Write the plain text lines back to the .env file
        let new_file_content = plain_lines.join("\n");
        fs::write(&env_file, new_file_content.as_bytes()).unwrap();
        // generate a new pair of keys
        let pair = EcKeyPair::generate();
        let pk_hex = pair.get_pk_hex();
        let sk_hex = pair.get_sk_hex();
        // update the public/private key in the .env file
        write_public_key_to_file(&env_file, &pk_hex).unwrap();
        let private_key_name = get_private_key_name_for_file(&env_file);
        write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &sk_hex).unwrap();
        // encrypt the .env file again
        if encrypt_mode {
            let file_content = fs::read_to_string(&env_file).unwrap();
            let entries = encrypt_env_entries(&env_file).unwrap();
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
            fs::write(&env_file, new_file_content.as_bytes()).unwrap();
        }
    } else {
        eprintln!("The specified .env file does not exist: {}", env_file);
        return;
    }
}
