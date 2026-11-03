use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::framework::detect_framework;
use crate::commands::{
    adjust_env_key, create_env_file, dotenv_double_quote, get_env_file_arg,
    get_or_create_public_key_for_file, get_public_key_for_file, is_sensitive_key, is_valid_env_key,
    properties_escape, replace_key_entries, resign_env_file_if_signed, shell_single_quote,
    update_env_file,
};
use arboard::Clipboard;
use clap::ArgMatches;
use std::io::Read;
use std::path::Path;
use std::{fs, io};

pub fn set_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let mut env_file = get_env_file_arg(command_matches, profile);
    let key_arg: String;
    let value: String;
    if let Some(key) = command_matches.get_one::<String>("key") {
        key_arg = key.to_string();
        let value_arg = command_matches
            .get_one::<String>("value")
            .map(|s| s.as_str());
        let mut input_value = value_arg.unwrap_or_default().to_string();
        // read from stdin if value is "-"
        if input_value == "-" {
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                eprintln!("Error: failed to read from stdin: {e}");
                std::process::exit(1);
            }
            // Trim the input to remove any trailing whitespace
            input_value = input.trim_end().to_string();
            if input_value.is_empty() {
                eprintln!("Error: value cannot be empty when reading from stdin.");
                return;
            }
        } else if command_matches.get_flag("clipboard") {
            if let Ok(mut clipboard) = Clipboard::new() {
                if let Ok(clipboard_text) = clipboard.get_text() {
                    input_value = clipboard_text.trim().to_string();
                    if let Err(e) = clipboard.clear() {
                        eprintln!("Warning: failed to clear clipboard: {e}");
                    }
                } else {
                    eprintln!("Failed to read from clipboard.");
                    std::process::exit(1);
                }
            }
        }
        value = input_value;
    } else {
        // read key and value from prompt
        println!("Please provide the key and value to set.");
        key_arg = match rprompt::prompt_reply("Key: ") {
            Ok(key) if !key.trim().is_empty() => key.trim().to_string(),
            Ok(_) => {
                eprintln!("Error: Key cannot be empty, please provide a key.");
                return;
            }
            Err(e) => {
                eprintln!("Error: failed to read key: {e}");
                std::process::exit(1);
            }
        };
        value = match rpassword::prompt_password("Value: ") {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error: failed to read value: {e}");
                std::process::exit(1);
            }
        };
    }
    if value.is_empty() {
        eprintln!("Error: Value cannot be empty, please provide a value.");
        return;
    }
    let key = adjust_env_key(&key_arg, &env_file);
    if !validate_key_name(&key, &env_file) {
        eprintln!(
            "Invalid key name: '{key}'. Key names must start with a letter or underscore and can only contain letters, numbers, and underscores."
        );
        return;
    }
    let is_stdout = command_matches.get_flag("stdout");
    // gofr reads `configs/.env*`: adjust the path before anything is computed from it
    if !is_stdout
        && !Path::new(&env_file).exists()
        && env_file.starts_with(".env")
        && detect_framework().is_some_and(|framework| framework == "gofr")
    {
        env_file = format!("configs/{env_file}");
    }
    let env_file_exists = Path::new(&env_file).exists();
    // encrypt the value or not based on the existing .env file content
    let mut encrypt_mode = is_sensitive_key(&key);
    let mut env_file_content = String::new();
    if env_file_exists {
        if let Ok(file_content) = fs::read_to_string(&env_file) {
            env_file_content = file_content;
        }
        // if encrypt_mode is false, check if the file contains any encrypted values
        if !encrypt_mode {
            encrypt_mode = env_file_content.contains("encrypted:");
        }
    }
    // check if _plain is present in the key name
    if key.to_lowercase().contains("_plain") {
        encrypt_mode = false;
    }
    // if encrypt or plain arg is provided, we override the encrypt_mode
    if command_matches.get_flag("plain") {
        encrypt_mode = false;
    }
    if command_matches.get_flag("encrypt") {
        encrypt_mode = true;
    }

    if is_stdout {
        // read-only: never generate or write a key pair in stdout mode
        let stored_value = if encrypt_mode {
            let public_key = match get_public_key_for_file(&env_file) {
                Ok(public_key) => public_key,
                Err(e) => {
                    eprintln!(
                        "Error: no public key found for {env_file}, please run `dotenvx init` first: {e}"
                    );
                    std::process::exit(1);
                }
            };
            encrypt_or_exit(&public_key, &value)
        } else {
            value
        };
        println!("export {key}={}", shell_single_quote(&stored_value));
        return;
    }

    let public_key = match get_or_create_public_key_for_file(&env_file) {
        Ok(public_key) => public_key,
        Err(e) => {
            eprintln!("Error: failed to get public key for {env_file}: {e}");
            std::process::exit(1);
        }
    };
    let stored_value = if encrypt_mode {
        encrypt_or_exit(&public_key, &value)
    } else {
        value
    };
    let quoted_value = if env_file.ends_with(".properties") {
        properties_escape(&stored_value)
    } else {
        dotenv_double_quote(&stored_value)
    };
    let make_pair = |has_export: bool| {
        let export = if has_export { "export " } else { "" };
        adjust_pair_for_file(&env_file, format!("{export}{key}={quoted_value}"))
    };
    if !env_file_exists {
        // create .env file if it does not exist
        create_env_file(
            &env_file,
            &public_key,
            Some(&make_pair(false)),
            &None,
            &None,
        );
        println!(
            "Added {key} to {env_file} with {} mode",
            if encrypt_mode { "encrypted" } else { "plain" }
        );
    } else if let Some(new_content) =
        replace_key_entries(&env_file_content, &env_file, &key, make_pair)
    {
        // Update existing key, multi-line values are replaced as a whole
        update_env_file(&env_file, &public_key, &new_content);
        resign_env_file_if_signed(&env_file, &env_file_content);
        println!("Updated {key} in {env_file}");
    } else {
        // Add new key
        let mut new_content = env_file_content.clone();
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&make_pair(false));
        update_env_file(&env_file, &public_key, &new_content);
        resign_env_file_if_signed(&env_file, &env_file_content);
        println!("Added {key} to {env_file}");
    }
}

fn encrypt_or_exit(public_key: &str, value: &str) -> String {
    match encrypt_env_item(public_key, value) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            eprintln!("Error: failed to encrypt value: {e}");
            std::process::exit(1);
        }
    }
}

pub fn validate_key_name(key: &str, env_file: &str) -> bool {
    if env_file.contains(".env") {
        is_valid_env_key(key)
    } else {
        true
    }
}

fn adjust_pair_for_file(env_file: &str, pair: String) -> String {
    if env_file.ends_with(".xml") {
        format!("<!-- {pair} -->")
    } else if env_file.ends_with(".sh") || env_file.ends_with(".toml") {
        format!("# {pair}")
    } else {
        pair
    }
}
#[cfg(test)]
mod tests {
    use crate::commands::set_cmd::validate_key_name;
    use crate::commands::{line_defines_key, properties_escape, replace_key_entries};

    #[test]
    fn test_validate_key_name() {
        for valid_key in ["KEY", "KEY_NAME", "KEY_NAME_123", "_KEY"] {
            assert!(validate_key_name(valid_key, ".env"), "{valid_key}");
        }
        for invalid_key in ["NO-WORK", "1KEY", "KEY NAME", ""] {
            assert!(!validate_key_name(invalid_key, ".env"), "{invalid_key}");
        }
        // only dotenv files restrict key names
        assert!(validate_key_name("NO-WORK", "application.properties"));
    }

    #[test]
    fn test_replace_multiline_value_and_keep_export() {
        let content = "A=1\nexport KEY=\"l1\nl2\"\nB=2";
        let replaced = replace_key_entries(content, ".env", "KEY", |export| {
            format!("{}KEY=\"new\"", if export { "export " } else { "" })
        });
        assert_eq!(replaced, Some("A=1\nexport KEY=\"new\"\nB=2".to_string()));
        assert_eq!(
            replace_key_entries(content, ".env", "C", |_| String::new()),
            None
        );
    }

    #[test]
    fn test_replace_properties_continuation() {
        let content = "a.b=1\nkey = x\\\n  y\\\\\nc: 2";
        let replaced = replace_key_entries(content, "application.properties", "key", |_| {
            "key=new".to_string()
        });
        // `y\\` ends with an escaped backslash, so the entry stops there
        assert_eq!(replaced, Some("a.b=1\nkey=new\nc: 2".to_string()));
        assert!(line_defines_key("application.properties", "c: 2", "c"));
        assert!(line_defines_key("application.properties", "c 2", "c"));
        assert!(!line_defines_key("application.properties", "c.d=2", "c"));
    }

    #[test]
    fn test_properties_escape() {
        assert_eq!(properties_escape("encrypted:abc$="), "encrypted:abc$=");
        assert_eq!(properties_escape(r"a\b"), r"a\\b");
        assert_eq!(properties_escape("  a b\nc"), r"\ \ a b\nc");
    }

    #[test]
    fn test_line_defines_key_embedded() {
        assert!(line_defines_key("a.sh", "# KEY=\"v\"", "KEY"));
        assert!(line_defines_key("a.xml", "<!-- KEY=\"v\" -->", "KEY"));
        assert!(!line_defines_key(".env", "# KEY=v", "KEY"));
    }
}
