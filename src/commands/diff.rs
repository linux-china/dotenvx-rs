use crate::commands::decrypt::decrypt_env_item;
use crate::commands::{get_private_key_for_file, read_dotenv_file};
use clap::ArgMatches;
use dotenvx_rs::common::get_profile_name_from_file;
use prettytable::{row, Table};

pub fn diff_command(command_matches: &ArgMatches) {
    let key_name = command_matches
        .get_one::<String>("key")
        .unwrap()
        .to_uppercase();
    let current_dir = std::env::current_dir().unwrap();
    let entries = walkdir::WalkDir::new(&current_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if e.file_type().is_file() {
                let file_name = e.file_name().to_str().unwrap();
                if file_name == ".env.keys" {
                    false
                } else {
                    file_name.starts_with(".env.") || file_name == ".env"
                }
            } else {
                false
            }
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        eprintln!("No .env files found.");
        return;
    }
    let mut table = Table::new();
    table.add_row(row!["Profile", key_name]);
    for entry in entries {
        let env_file_name = entry.file_name().to_str().unwrap();
        let entries = read_dotenv_file(env_file_name).unwrap();
        let profile_name = get_profile_name_from_file(env_file_name).unwrap_or("".to_string());
        if let Some(value) = entries.get(&key_name) {
            let mut plain_value = value.to_string();
            if value.starts_with("encrypted:") {
                if let Ok(private_key) = get_private_key_for_file(env_file_name) {
                    plain_value = decrypt_env_item(&private_key, value).unwrap_or(value.clone());
                }
            }
            table.add_row(row![profile_name, plain_value]);
        } else {
            table.add_row(row![profile_name, ""]);
        }
    }
    table.printstd();
}
