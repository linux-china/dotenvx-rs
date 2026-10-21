use crate::commands::crypt_util::decrypt_env_item;
use crate::commands::{get_private_key_for_file, list_env_files, read_dotenv_file};
use clap::ArgMatches;
use dotenvx_rs::common::get_profile_name_from_file;
use comfy_table::Table;
use std::io;

pub fn diff_command(command_matches: &ArgMatches) {
    let format = if let Some(arg_value) = command_matches.get_one::<String>("format") {
        arg_value.clone()
    } else {
        "text".to_owned()
    };
    let key_names = command_matches
        .get_one::<String>("keys")
        .unwrap()
        .to_uppercase();
    let key_names = key_names.split(',').collect::<Vec<&str>>();
    let current_dir = std::env::current_dir().unwrap();
    let entries = list_env_files(current_dir, 1, &None);
    if entries.is_empty() {
        eprintln!("No .env files found.");
        return;
    }
    let mut header_row = vec!["profile".to_string()];
    for key_name in &key_names {
        header_row.push(key_name.to_string());
    }
    let mut rows: Vec<Vec<String>> = vec![];
    for entry in entries {
        let env_file_name = entry.file_name().to_str().unwrap();
        let entries = read_dotenv_file(env_file_name).unwrap();
        let profile_name = get_profile_name_from_file(env_file_name).unwrap_or("".to_string());
        let mut data_row = vec![profile_name];
        for key_name in &key_names {
            if let Some(value) = entries.get(*key_name) {
                let mut plain_value = value.to_string();
                if value.starts_with("encrypted:") {
                    if let Ok(private_key) = get_private_key_for_file(env_file_name) {
                        plain_value =
                            decrypt_env_item(&private_key, value).unwrap_or(value.clone());
                    }
                }
                data_row.push(plain_value);
            } else {
                data_row.push("".to_string());
            }
        }
        rows.push(data_row);
    }
    if format == "csv" {
        let mut writer = csv::Writer::from_writer(io::stdout());
        writer.write_record(&header_row).unwrap();
        for row in &rows {
            writer.write_record(row).unwrap();
        }
        writer.flush().unwrap();
    } else {
        let mut table = Table::new();
        table.set_header(header_row);
        table.add_rows(rows);
        println!("{table}");
    }
}
