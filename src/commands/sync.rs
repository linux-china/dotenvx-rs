use crate::commands::crypt_util::{EcKeyPair, decrypt_env_item, encrypt_env_item};
use crate::commands::decrypt::{parse_env_entry, read_env_items};
use crate::commands::encrypt::inline_comment;
use crate::commands::model::KeyPair;
use crate::commands::{
    KEYS_FILE_NAME, construct_env_file_header, dotenv_double_quote, entry_line_count,
    get_dotenvx_home, get_private_key_for_file, get_private_key_name_for_file,
    get_public_key_for_file, get_public_key_name_for_file, is_public_key_name, is_sensitive_key,
    private_key_exists_in_file, split_assignment, write_key_pair, write_private_key_to_file,
};
use clap::ArgMatches;
use colored_json::Paint;
use dotenvx_rs::common::get_profile_name_from_file;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("{}", format!("✘ {message}").red());
    std::process::exit(1);
}

/// The private key of `source`, only looked up when `items` hold an `encrypted:` value.
fn source_private_key(source: &str, items: &HashMap<String, String>) -> Option<String> {
    if !items.values().any(|v| v.starts_with("encrypted:")) {
        return None;
    }
    match get_private_key_for_file(source) {
        Ok(private_key) => Some(private_key),
        Err(e) => fail(format!("failed to find the private key of {source}: {e}")),
    }
}

/// The plain value of a raw source value: `encrypted:` values are decrypted with `private_key`.
fn plain_value(key: &str, raw_value: &str, private_key: Option<&str>) -> String {
    if !raw_value.starts_with("encrypted:") {
        return raw_value.to_string();
    }
    // source_private_key() always returns a key when an encrypted value exists
    let private_key = private_key.unwrap_or_default();
    decrypt_env_item(private_key, raw_value)
        .unwrap_or_else(|e| fail(format!("failed to decrypt {key}: {e}")))
}

fn encrypt_or_fail(public_key: &str, key: &str, value: &str) -> String {
    encrypt_env_item(public_key, value)
        .unwrap_or_else(|e| fail(format!("failed to encrypt {key}: {e}")))
}

/// Keys of the assignments of `env_file` in file order, duplicates removed.
fn ordered_keys(env_file: &str) -> Vec<String> {
    let content = fs::read_to_string(env_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    let mut i = 0;
    while i < lines.len() {
        let assignment = split_assignment(env_file, lines[i]);
        let line_count = if assignment.is_some() {
            entry_line_count(env_file, &lines, i)
        } else {
            1
        };
        if let Some((_, key, _)) = assignment
            && seen.insert(key.to_string())
        {
            keys.push(key.to_string());
        }
        i += line_count.max(1);
    }
    keys
}

pub fn sync_command(command_matches: &ArgMatches) {
    let source = command_matches
        .get_one::<String>("source")
        .unwrap()
        .to_string();
    let target = command_matches
        .get_one::<String>("target")
        .unwrap()
        .to_string();
    if !Path::new(&source).exists() {
        fail(format!("Source file '{source}' does not exist."));
    }
    if Path::new(&target).exists() {
        sync_to_existing_target(&source, &target);
    } else {
        sync_to_new_target(&source, &target);
    }
}

/// Create `target` from `source` with a new key pair: every value that is encrypted in `source`
/// (and every plain sensitive value) is encrypted with the new public key, other lines are kept
/// verbatim, `export` prefixes and multi-line values included (review 1.2).
fn sync_to_new_target(source: &str, target: &str) {
    let profile = get_profile_name_from_file(target);
    let target_file_path = Path::new(target);
    // `sub/.env` maps to `DOTENV_PRIVATE_KEY` too: never replace an existing key (review #1)
    let private_key_name = get_private_key_name_for_file(target);
    if private_key_exists_in_file(KEYS_FILE_NAME, &private_key_name) {
        fail(format!(
            "{private_key_name} already exists in {KEYS_FILE_NAME}, refusing to overwrite it. Please use another target file name or run sync in the directory of {target}."
        ));
    }
    let source_file_content = fs::read_to_string(source)
        .unwrap_or_else(|e| fail(format!("failed to read {source}: {e}")));
    let source_items =
        read_env_items(source).unwrap_or_else(|e| fail(format!("failed to parse {source}: {e}")));
    let private_key = source_private_key(source, &source_items);
    let kp = EcKeyPair::generate();
    let new_public_key = kp.get_pk_hex();
    let is_properties = source.ends_with(".properties");

    let mut lines: Vec<&str> = source_file_content.lines().collect();
    // drop the header of the source: everything up to its public key
    if let Some(pos) = lines.iter().position(|line| {
        split_assignment(source, line).is_some_and(|(_, key, _)| is_public_key_name(key))
    }) {
        lines = lines[pos + 1..].to_vec();
    }
    let mut new_lines: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let assignment = split_assignment(source, lines[i]);
        let line_count = if assignment.is_some() {
            entry_line_count(source, &lines, i)
        } else {
            1
        };
        let end = (i + line_count.max(1)).min(lines.len());
        let entry_text = lines[i..end].join("\n");
        match assignment {
            Some((_, key, _)) if is_public_key_name(key) => {}
            Some((prefix, key, value_text)) => {
                let raw_value = parse_env_entry(&entry_text, is_properties);
                let needs_encryption = raw_value
                    .as_deref()
                    .is_some_and(|v| v.starts_with("encrypted:") || is_sensitive_key(key));
                if let (true, Some(raw_value)) = (needs_encryption, raw_value) {
                    let value = plain_value(key, &raw_value, private_key.as_deref());
                    let encrypted = encrypt_or_fail(&new_public_key, key, &value);
                    let new_line = if is_properties {
                        format!("{prefix}{key}={encrypted}")
                    } else {
                        let mut entry_value = value_text.to_string();
                        for line in &lines[i + 1..end] {
                            entry_value.push('\n');
                            entry_value.push_str(line);
                        }
                        match inline_comment(&entry_value) {
                            Some(comment) => format!("{prefix}{key}=\"{encrypted}\" {comment}"),
                            None => format!("{prefix}{key}=\"{encrypted}\""),
                        }
                    };
                    new_lines.push(new_line);
                } else {
                    new_lines.push(entry_text);
                }
            }
            None => {
                if !lines[i].starts_with("# Environment variables") {
                    new_lines.push(entry_text);
                }
            }
        }
        i = end;
    }
    let header = construct_env_file_header(
        &get_public_key_name_for_file(target),
        &new_public_key,
        &None,
        &None,
    );
    let new_content = format!("{}\n{}\n", header.trim(), new_lines.join("\n").trim());
    if let Err(e) = fs::write(target_file_path, new_content.as_bytes()) {
        fail(format!("failed to write {target}: {e}"));
    }
    println!(
        "{}",
        format!("✔ target env file '{target}' created.").green()
    );
    // write key pair
    let mut key_pair = KeyPair::from(&new_public_key, &kp.get_sk_hex(), &None, &None, &profile);
    if let Ok(absolute_path) = fs::canonicalize(target_file_path) {
        key_pair.path = Some(absolute_path.to_string_lossy().to_string());
    }
    if PathBuf::from(KEYS_FILE_NAME).exists() {
        // local .env.keys
        if let Err(e) =
            write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &key_pair, false)
        {
            fail(format!(
                "Failed to write private key to {KEYS_FILE_NAME}: {e}"
            ));
        }
    } else {
        // global key store
        if let Err(e) = write_key_pair(&key_pair) {
            fail(format!("Failed to save the private key of {target}: {e}"));
        }
        let private_key_short = &key_pair.private_key[0..6];
        println!(
            "{}",
            format!(
                "✔ private key({private_key_short}) saved to {}",
                get_dotenvx_home().join(".env.keys.json").display()
            )
            .green()
        );
    }
}

/// Append the keys of `source` that are absent in `target`. A value that is encrypted in `source`
/// is encrypted with the public key of `target`, never written as plain text (review 1.2).
fn sync_to_existing_target(source: &str, target: &str) {
    let source_items =
        read_env_items(source).unwrap_or_else(|e| fail(format!("failed to parse {source}: {e}")));
    // only the keys of the target are needed: its private key is not required
    let target_items =
        read_env_items(target).unwrap_or_else(|e| fail(format!("failed to parse {target}: {e}")));
    let target_public_key = get_public_key_for_file(target).unwrap_or_default();
    let absent_keys: Vec<String> = ordered_keys(source)
        .into_iter()
        .filter(|key| {
            !is_public_key_name(key)
                && source_items.contains_key(key)
                && !target_items.contains_key(key)
        })
        .collect();
    if target_public_key.is_empty() {
        let encrypted_keys: Vec<&str> = absent_keys
            .iter()
            .filter(|key| source_items[*key].starts_with("encrypted:"))
            .map(String::as_str)
            .collect();
        if !encrypted_keys.is_empty() {
            fail(format!(
                "{target} has no public key, refusing to write encrypted values of {source} as plain text: {}. Please run `dotenvx encrypt -f {target}` first.",
                encrypted_keys.join(", ")
            ));
        }
    }
    let private_key = if absent_keys
        .iter()
        .any(|key| source_items[key].starts_with("encrypted:"))
    {
        source_private_key(source, &source_items)
    } else {
        None
    };
    let mut absent_variables: Vec<String> = Vec::new();
    for key in &absent_keys {
        let raw_value = &source_items[key];
        let value = plain_value(key, raw_value, private_key.as_deref());
        let needs_encryption = raw_value.starts_with("encrypted:") || is_sensitive_key(key);
        if needs_encryption && !target_public_key.is_empty() {
            let encrypted_value = encrypt_or_fail(&target_public_key, key, &value);
            absent_variables.push(format!("{key}=\"{encrypted_value}\""));
        } else {
            absent_variables.push(format!("{key}={}", dotenv_double_quote(&value)));
        }
    }
    if absent_variables.is_empty() {
        println!("{}", format!("✔ no changes ({target})").green());
        return;
    }
    let target_file_content = fs::read_to_string(target)
        .unwrap_or_else(|e| fail(format!("failed to read {target}: {e}")));
    let separator = if target_file_content.is_empty() || target_file_content.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let new_content = format!(
        "{target_file_content}{separator}{}\n",
        absent_variables.join("\n")
    );
    if let Err(e) = fs::write(target, new_content.as_bytes()) {
        fail(format!("failed to write {target}: {e}"));
    }
    println!(
        "{}",
        format!(
            "✔ target env file '{target}' updated, added keys: {}",
            absent_keys.join(", ")
        )
        .green()
    );
}
