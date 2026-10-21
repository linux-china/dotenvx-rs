use crate::commands::{adjust_env_key, get_env_file_arg, is_valid_env_key};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

pub fn del_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    if !env_file.contains(".env") {
        eprintln!("Error: .env supported only");
        return;
    }
    let key_arg = command_matches
        .get_one::<String>("key")
        .map(|s| s.to_string());
    let key = adjust_env_key(&key_arg.unwrap(), &env_file);
    if !validate_key_name(&key, &env_file) {
        eprintln!(
            "Invalid key name: '{key}'. Key names must start with a letter or underscore and can only contain letters, numbers, and underscores."
        );
        return;
    }
    let env_file_exists = Path::new(&env_file).exists();
    let mut env_file_content = String::new();
    if env_file_exists {
        if let Ok(file_content) = fs::read_to_string(&env_file) {
            env_file_content = file_content;
        }
    }
    if let Some(new_content) = remove_key_lines(&env_file_content, &env_file, &key) {
        fs::write(&env_file, new_content).unwrap();
        println!("{key} deleted from {env_file}");
    } else {
        eprintln!("Key '{key}' not found in {env_file}");
    }
}

pub fn validate_key_name(key: &str, env_file: &str) -> bool {
    if env_file.contains(".env") {
        is_valid_env_key(key)
    } else {
        true
    }
}

fn remove_key_lines(content: &str, _env_file: &str, key: &str) -> Option<String> {
    let line_prefix = format!("{key}=");
    let mut removed = false;
    let new_content = content
        .split_inclusive('\n')
        .filter(|line| {
            let matches = line
                .trim_end_matches(['\r', '\n'])
                .trim_start()
                .starts_with(&line_prefix);
            removed |= matches;
            !matches
        })
        .collect();

    removed.then_some(new_content)
}

#[cfg(test)]
mod tests {
    use super::remove_key_lines;

    #[test]
    fn removes_only_exact_env_key_lines() {
        let content = "KEY=value\nKEY_SUFFIX=kept\nOTHER=KEY=value\n";

        assert_eq!(
            remove_key_lines(content, ".env", "KEY"),
            Some("KEY_SUFFIX=kept\nOTHER=KEY=value\n".to_string())
        );
    }

    #[test]
    fn preserves_line_endings_and_removes_duplicate_key_lines() {
        let content = "KEY=first\r\nOTHER=value\r\nKEY=second";

        assert_eq!(
            remove_key_lines(content, ".env", "KEY"),
            Some("OTHER=value\r\n".to_string())
        );
    }

    #[test]
    fn returns_none_when_key_is_absent() {
        assert_eq!(remove_key_lines("OTHER=value\n", ".env", "KEY"), None);
    }
}
