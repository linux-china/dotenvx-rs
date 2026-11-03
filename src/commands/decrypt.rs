use crate::commands::crypt_util::{decrypt_env_item, decrypt_value};
use crate::commands::model::EnvFile;
use crate::commands::{
    compile_key_patterns, dotenv_double_quote, entry_line_count, get_env_file_arg, get_private_key,
    get_private_key_for_file, get_private_key_for_public_key, get_public_key_from_text_file,
    get_public_key_name_for_file, is_encrypted_value_text, is_public_key_name, is_remote_env_file,
    properties_escape, read_content_from_dotenv_url, resign_env_file_if_signed, split_assignment,
    std_output,
};
use clap::ArgMatches;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_file;
use java_properties::PropertiesIter;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Cursor;

pub fn decrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    if let Some(arg_value) = command_matches.get_one::<String>("value") {
        decrypt_value(profile, arg_value);
        return;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    if command_matches.get_flag("verify") {
        verify_signature(&env_file);
        return;
    }
    let is_stdout = command_matches.get_flag("stdout");
    let is_dump = command_matches.get_flag("dump");
    let is_remote_env = is_remote_env_file(&env_file);
    // a remote env file can't be written back: only print the decrypted content (review 2.7)
    if is_remote_env && !is_stdout && !is_dump {
        eprintln!(
            "{}",
            format!("✘ remote env file can only be decrypted with --stdout or --dump ({env_file})")
                .red()
        );
        std::process::exit(1);
    }
    let file_name = env_file_name(&env_file);
    if !is_remote_env {
        if !std::path::Path::new(&env_file).exists() {
            eprintln!(
                "{}",
                format!("✘ The specified env file '{env_file}' does not exist.").red()
            );
            std::process::exit(1);
        }
        // decrypt normal text file if not .env or .properties file
        if !file_name.starts_with(".env") && !file_name.ends_with(".properties") {
            decrypt_normal_text_file(&env_file);
            return;
        }
    }
    let is_properties = file_name.ends_with(".properties");
    // read the content once: the remote file is fetched once, and the entries match the rewritten lines
    let file_content = match read_env_content(&env_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("{}", format!("✘ failed to read {env_file}: {e}").red());
            std::process::exit(1);
        }
    };
    // in file order, a key may occur more than once (review #1)
    let ordered_entries = match decrypt_env_content_ordered(&env_file, &file_content) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("{}", format!("✘ failed to decrypt {env_file}: {e}").red());
            std::process::exit(1);
        }
    };
    let mut entries: HashMap<String, String> = ordered_entries.iter().cloned().collect();
    let env_keys = command_matches.get_many::<String>("keys");
    let mut hint = format!(".env file({env_file})");
    if let Some(keys) = env_keys {
        let patterns = match compile_key_patterns(keys, &env_file) {
            Ok(patterns) => patterns,
            Err(e) => {
                eprintln!("{}", format!("✘ {e}").red());
                std::process::exit(1);
            }
        };
        entries.retain(|key, _| patterns.matches(key));
        hint = format!("keys in .env file: {env_file}");
    }
    // check dump flag
    if is_dump {
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        std_output(&entries, &Some(&"json".to_string()));
        return;
    }
    // stdout with format shell, json or csv
    if is_stdout
        && let Some(fmt) = command_matches.get_one::<String>("format")
        && fmt != "text"
    {
        std_output(&entries, &Some(fmt));
        if fmt == "shell" {
            println!("# Run this command to configure your shell:");
            println!("# eval $(dotenvx decrypt -f {env_file} --stdout --format shell)");
        }
        return;
    }
    // split_assignment detects .properties by the suffix, a URL may end with a query string
    let syntax_hint = if is_properties { ".properties" } else { ".env" };
    // every occurrence of a key is decrypted with its own value, consumed in file order (review #1)
    let mut values: HashMap<String, VecDeque<String>> = HashMap::new();
    for (key, value) in ordered_entries {
        values.entry(key).or_default().push_back(value);
    }
    let lines: Vec<&str> = file_content.lines().collect();
    let mut new_lines: Vec<String> = Vec::new();
    let mut is_changed = false;
    let mut i = 0;
    // only `encrypted:` values are rewritten, keeping indentation and the `export ` prefix (review #1)
    while i < lines.len() {
        let assignment = split_assignment(syntax_hint, lines[i]);
        let line_count = if assignment.is_some() {
            entry_line_count(syntax_hint, &lines, i)
        } else {
            1
        };
        let end = (i + line_count).min(lines.len());
        let replacement = assignment.and_then(|(prefix, key, value_text)| {
            // consume this occurrence's value even when the entry is kept, so that later
            // occurrences of the same key stay aligned with the parser
            let value = values.get_mut(key).and_then(VecDeque::pop_front)?;
            if !is_encrypted_value_text(value_text) || !entries.contains_key(key) {
                return None;
            }
            let new_value = if is_properties {
                properties_escape(&value)
            } else {
                dotenv_double_quote(&value)
            };
            Some(format!("{prefix}{key}={new_value}"))
        });
        if let Some(new_line) = replacement {
            // the whole entry is replaced, continuation lines of a wrapped ciphertext included
            new_lines.push(new_line);
            is_changed = true;
        } else {
            new_lines.extend(lines[i..end].iter().map(|l| l.to_string()));
        }
        i = end;
    }
    // stdout with text format
    if is_stdout {
        for line in new_lines {
            println!("{line}");
        }
        return;
    }
    if !is_changed {
        println!("{}", format!("✔ no changes ({env_file})").green());
        return;
    }
    let mut new_file_content = new_lines.join("\n");
    if file_content.ends_with('\n') {
        new_file_content.push('\n');
    }
    // decrypted .env now holds plaintext secrets, write it owner-only on Unix
    if let Err(e) = crate::commands::write_private_file(&env_file, new_file_content.as_bytes()) {
        eprintln!("{}", format!("✘ failed to write {env_file}: {e}").red());
        std::process::exit(1);
    }
    println!("{}", format!("✔ {hint} decrypted ({env_file})").green());
    resign_env_file_if_signed(&env_file, &file_content);
}

/// File name of a local path or the last path segment of a URL (query and fragment removed).
fn env_file_name(env_file: &str) -> String {
    let path = if is_remote_env_file(env_file) {
        env_file.split(['?', '#']).next().unwrap_or(env_file)
    } else {
        env_file
    };
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_string()
}

fn read_env_content(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    if is_remote_env_file(env_file) {
        read_content_from_dotenv_url(env_file, None)
    } else {
        Ok(fs::read_to_string(env_file)?)
    }
}

pub fn decrypt_env_entries(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let content = read_env_content(env_file)?;
    decrypt_env_content(env_file, &content)
}

/// The raw (not decrypted) entries of `env_file`: `encrypted:` values are kept as they are.
pub fn read_env_items(
    env_file: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let content = read_env_content(env_file)?;
    parse_env_content(&content, env_file_name(env_file).ends_with(".properties"))
}

/// Parse the text of a single entry (continuation lines included), `None` if it holds no assignment.
pub fn parse_env_entry(entry_text: &str, is_properties: bool) -> Option<String> {
    parse_env_content(entry_text, is_properties)
        .ok()?
        .into_values()
        .next()
}

/// Parse `content` (the content of `env_file`, a local path or a URL) and decrypt its `encrypted:` values.
fn decrypt_env_content(
    env_file: &str,
    content: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    Ok(decrypt_env_content_ordered(env_file, content)?
        .into_iter()
        .collect())
}

/// Like [`decrypt_env_content`], but keeps the entries in file order, duplicated keys included.
fn decrypt_env_content_ordered(
    env_file: &str,
    content: &str,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let is_properties = env_file_name(env_file).ends_with(".properties");
    let items = parse_env_content_ordered(content, is_properties)?;
    if !items.iter().any(|(_, v)| v.starts_with("encrypted:")) {
        return Ok(items);
    }
    let private_key = if is_remote_env_file(env_file) {
        let item_map: HashMap<String, String> = items.iter().cloned().collect();
        private_key_for_remote(env_file, &item_map)?
    } else {
        get_private_key_for_file(env_file)?
    };
    items
        .into_iter()
        .map(|(key, value)| {
            if value.starts_with("encrypted:") {
                let plain = decrypt_env_item(&private_key, &value)
                    .map_err(|e| format!("failed to decrypt {key}: {e}"))?;
                Ok((key, plain))
            } else {
                Ok((key, value))
            }
        })
        .collect()
}

fn parse_env_content(
    content: &str,
    is_properties: bool,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    Ok(parse_env_content_ordered(content, is_properties)?
        .into_iter()
        .collect())
}

/// The entries of `content` in file order, a duplicated key occurs once per assignment.
fn parse_env_content_ordered(
    content: &str,
    is_properties: bool,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut entries: Vec<(String, String)> = Vec::new();
    if is_properties {
        PropertiesIter::new(Cursor::new(content.as_bytes())).read_into(|key, value| {
            let value = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                Some(unquoted) => unquoted.to_string(),
                None => value,
            };
            entries.push((key, value));
        })?;
    } else {
        for item in dotenvy::from_read_iter(Cursor::new(content.as_bytes())) {
            entries.push(item?);
        }
    }
    Ok(entries)
}

/// The private key of a remote env file: matched against the public key declared in the remote content,
/// never against a local file with the same name (review 2.7).
fn private_key_for_remote(
    env_file: &str,
    items: &HashMap<String, String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let file_name = env_file_name(env_file);
    let profile_name = get_profile_name_from_file(&file_name);
    let clean = |v: &String| v.trim().trim_matches('"').to_owned();
    let mut public_key = items
        .get(&get_public_key_name_for_file(&file_name))
        .map(clean)
        .filter(|v| !v.is_empty());
    if public_key.is_none() {
        let mut keys: Vec<String> = items
            .iter()
            .filter(|(k, _)| is_public_key_name(k))
            .map(|(_, v)| clean(v))
            .filter(|v| !v.is_empty())
            .collect();
        keys.sort();
        keys.dedup();
        if keys.len() == 1 {
            public_key = keys.pop();
        }
    }
    match public_key {
        Some(public_key) => get_private_key_for_public_key(&public_key, &profile_name, None),
        None => get_private_key(&profile_name),
    }
}

/// Check the signature of the env file, exit with 1 if the file is unsigned, the signature is invalid
/// or the file can't be parsed, same as the `verify` sub command (review #9).
fn verify_signature(env_file_path: &str) {
    let Ok(env_file) = EnvFile::from(env_file_path) else {
        eprintln!(
            "{}",
            format!("✘ Failed to parse the env file: {env_file_path}").red()
        );
        std::process::exit(1);
    };
    if !env_file.is_signed() {
        eprintln!(
            "{}",
            format!("✘ The env file is not signed ({env_file_path})").red()
        );
        std::process::exit(1);
    }
    if !env_file.is_verified() {
        eprintln!(
            "{}",
            format!("✘ The env file is signed, but the signature is invalid ({env_file_path})")
                .red()
        );
        std::process::exit(1);
    }
    println!(
        "{}",
        format!("✔ The env file is signed, and the signature is valid ({env_file_path})").green()
    );
}

fn decrypt_normal_text_file(text_file_path: &str) {
    if let Some(public_key) = get_public_key_from_text_file(text_file_path) {
        let profile_name = get_profile_name_from_file(text_file_path);
        if let Ok(private_key) =
            get_private_key_for_public_key(&public_key, &profile_name, Some(text_file_path))
        {
            if let Ok(file_content) = fs::read_to_string(text_file_path) {
                file_content.lines().for_each(|line| {
                    if line.contains("encrypted:") {
                        let parts: Vec<&str> = line.splitn(2, "encrypted:").collect();
                        let parts2 = parts[1];
                        let values: Vec<&str> = parts2
                            .splitn(2, [' ', '\'', '"', '<', '>'].as_slice())
                            .collect();
                        let encrypted_value = values[0];
                        if let Ok(plain_value) = decrypt_env_item(&private_key, encrypted_value) {
                            println!(
                                "{}",
                                line.replace(&format!("encrypted:{encrypted_value}"), &plain_value)
                            );
                        } else {
                            println!("{line}")
                        }
                    } else {
                        println!("{line}");
                    }
                })
            } else {
                eprintln!("Failed to read the text file: {text_file_path}");
            }
        } else {
            eprintln!("Failed to get private key for the public key: {public_key}");
        }
    } else {
        eprintln!("Failed to get public key from the text file: {text_file_path}");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_decrypt_dotenv() {
        let entries = super::decrypt_env_entries(".env").unwrap();
        println!("{entries:?}");
    }

    #[test]
    fn parse_keeps_duplicated_keys_in_order() {
        let entries = super::parse_env_content_ordered("X=one\nY=keep\nX=two\n", false).unwrap();
        let expected = [("X", "one"), ("Y", "keep"), ("X", "two")];
        assert_eq!(
            entries,
            expected.map(|(k, v)| (k.to_string(), v.to_string()))
        );
        let entries = super::parse_env_content_ordered("a=one\na=two\n", true).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, "one");
    }

    #[test]
    fn decrypt_text_file() {
        super::decrypt_normal_text_file("tests/demo.xml");
    }
}
