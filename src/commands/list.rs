use clap::ArgMatches;
use colored::Colorize;

pub fn ls_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let directory = command_matches
        .get_one::<String>("directory")
        .map(|s| s.as_str())
        .unwrap_or(".");
    // list all .env files in directory by walkdir
    let entries = walkdir::WalkDir::new(directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if e.file_type().is_file() {
                let file_name = e.file_name().to_str().unwrap();
                if let Some(profile_name) = profile {
                    file_name.starts_with(&format!(".env.{}", profile_name))
                } else if file_name == ".env.keys" {
                    false
                } else {
                    file_name == ".env" || file_name.starts_with(".env.")
                }
            } else {
                false
            }
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        println!("No .env files found in directory: {}", directory);
        return;
    } else {
        println!(
            "Found {} .env files in '{}' directory:",
            entries.len(),
            directory
        );
        let mut all_names: Vec<&str> = entries
            .iter()
            .map(|e| e.path().to_str().unwrap().trim_start_matches("./"))
            .collect();
        all_names.sort();
        for file_path in all_names {
            if file_path.ends_with(".env.keys") {
                println!("- {}", file_path.red());
            } else {
                println!("- {}", file_path.green());
            }
        }
    }
}
