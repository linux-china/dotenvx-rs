use crate::commands::model::EnvFile;
use clap::ArgMatches;
use prettytable::format::Alignment;
use prettytable::{row, Cell, Row, Table};
use walkdir::DirEntry;

pub fn ls_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let directory = command_matches
        .get_one::<String>("directory")
        .map(|s| s.as_str())
        .unwrap_or(".");
    // list all .env files in directory by walkdir
    let mut entries: Vec<DirEntry> = walkdir::WalkDir::new(directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let file_name = e.file_name().to_str().unwrap();
            if file_name == ".env.keys" {
                false
            } else {
                file_name.starts_with(".env.") || file_name == ".env"
            }
        })
        .filter(|e| {
            // filter by profile if provided
            let file_name = e.file_name().to_str().unwrap();
            if let Some(profile_name) = profile {
                let env_file_name = format!(".env.{profile_name}");
                file_name.starts_with(&env_file_name)
            } else {
                true
            }
        })
        .collect();
    if entries.is_empty() {
        println!("No .env files found in directory: {directory}");
    } else {
        entries.sort_by_key(|entry| {
            entry
                .path()
                .to_str()
                .unwrap()
                .trim_start_matches("./")
                .to_string()
        });
        let title = format!(
            "Found {} .env files in '{}' directory:",
            entries.len(),
            directory
        );
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new_align(&title, Alignment::CENTER).with_hspan(6),
        ]));
        table.add_row(row![
            "Path",
            "UUID",
            "Entries",
            "Public Key",
            "Signed",
            "Verified"
        ]);
        for entry in entries {
            let file_path = entry.path().to_str().unwrap();
            let env_file = EnvFile::from(file_path).unwrap();
            let display_name = file_path.trim_start_matches("./");
            let file_uuid = if let Some(uuid) = env_file.get_uuid() {
                uuid.to_string()
            } else {
                "N/A".to_string()
            };
            let entry_count = env_file.entries.len();
            let public_key_short = if let Some(public_key) = env_file.get_public_key() {
                if public_key.len() > 8 {
                    format!("{}...", &public_key[0..8])
                } else {
                    public_key.to_string()
                }
            } else {
                "N/A".to_string()
            };
            let sign_symbol = if env_file.is_signed() { "Yes" } else { "No" };
            let verified = if sign_symbol == "Yes" {
                if env_file.is_verified() {
                    "Yes"
                } else {
                    "Fail"
                }
            } else {
                "N/A"
            };

            table.add_row(row![
                display_name,
                file_uuid,
                entry_count,
                public_key_short,
                sign_symbol,
                verified
            ]);
        }
        table.printstd();
    }
}
