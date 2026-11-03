use crate::commands::{
    adjust_env_key, get_env_file_arg, is_valid_env_key, remove_key_entries,
    resign_env_file_if_signed,
};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

pub fn del_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    // `remove_key_entries` handles both `.env` and `.properties`, see review #27
    if !env_file.contains(".env") && !env_file.ends_with(".properties") {
        eprintln!("Error: only .env and .properties files are supported");
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
    if let Some(new_content) = remove_key_entries(&env_file_content, &env_file, &key) {
        if let Err(e) = fs::write(&env_file, new_content) {
            eprintln!("Error: failed to write {env_file}: {e}");
            std::process::exit(1);
        }
        resign_env_file_if_signed(&env_file, &env_file_content);
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

#[cfg(test)]
mod tests {
    use crate::commands::remove_key_entries as remove_key_lines;

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
    fn removes_properties_key_with_continuation() {
        let content = "a=1\nkey = line1 \\\n  line2\nkey.sub=kept\nb: 2\n";
        assert_eq!(
            remove_key_lines(content, "application.properties", "key"),
            Some("a=1\nkey.sub=kept\nb: 2\n".to_string())
        );
        assert_eq!(
            remove_key_lines(content, "application.properties", "b"),
            Some("a=1\nkey = line1 \\\n  line2\nkey.sub=kept\n".to_string())
        );
    }

    #[test]
    fn returns_none_when_key_is_absent() {
        assert_eq!(remove_key_lines("OTHER=value\n", ".env", "KEY"), None);
    }

    #[test]
    fn removes_spaced_and_exported_keys() {
        let content = "KEY = v1\nexport KEY=v2\nOTHER=1\n# KEY=commented\n";
        assert_eq!(
            remove_key_lines(content, ".env", "KEY"),
            Some("OTHER=1\n# KEY=commented\n".to_string())
        );
    }

    #[test]
    fn removes_multiline_value_continuations() {
        let content = "A=1\nKEY=\"line1\nline2\nline3\"\nB='x\ny'\nC=2\n";
        assert_eq!(
            remove_key_lines(content, ".env", "KEY"),
            Some("A=1\nB='x\ny'\nC=2\n".to_string())
        );
        assert_eq!(
            remove_key_lines(content, ".env", "B"),
            Some("A=1\nKEY=\"line1\nline2\nline3\"\nC=2\n".to_string())
        );
    }

    #[test]
    fn escaped_quote_does_not_close_value() {
        let content = "KEY=\"a\\\"b\nc\"\nC=2\n";
        assert_eq!(
            remove_key_lines(content, ".env", "KEY"),
            Some("C=2\n".to_string())
        );
    }
}
