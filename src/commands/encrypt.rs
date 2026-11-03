use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::model::sign_and_update_env_file_content;
use crate::commands::{
    adjust_env_key, construct_env_file_header, entry_line_count, get_env_file_arg,
    get_or_create_public_key_for_file, get_private_key_for_file, get_public_key_name_for_file,
    content_has_key, is_encrypted_value_text, is_public_key_name, split_assignment,
    update_env_file, write_public_key_to_file,
};
use clap::ArgMatches;
use colored_json::Paint;
use glob::Pattern;
use java_properties::PropertiesIter;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;

pub fn encrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let env_keys = command_matches.get_many::<String>("keys");
    let is_stdout = command_matches.get_flag("stdout");
    let is_sign_required = command_matches.get_flag("sign");
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !env_file_path.exists() {
        // create default env file if it does not exist
        let public_key = get_or_create_public_key_for_file(&env_file).unwrap();
        println!("'{env_file}' does not exist, creating a new file with public key.");
        write_public_key_to_file(&env_file_path, &public_key).unwrap();
        return;
    }
    let mut is_changed = false;
    let file_content = fs::read_to_string(&env_file_path).unwrap();
    // resolve the public key only once for the whole command
    let public_key = get_or_create_public_key_for_file(&env_file).unwrap();
    let mut entries = match encrypt_env_entries(&env_file, &public_key) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error: failed to parse {env_file}: {e}");
            std::process::exit(1);
        }
    };
    let mut hint = format!(".env file({env_file})");
    if let Some(keys) = env_keys {
        let patterns: Vec<Pattern> = keys
            .map(|x| adjust_env_key(x, &env_file))
            .map(|x| Pattern::new(&x).unwrap())
            .collect();
        entries.retain(|key, _| patterns.iter().any(|pattern| pattern.matches(key)));
        hint = format!("keys in .env file: {env_file}");
    }
    // only entries encrypted by this run are rewritten, every other line is kept verbatim (review #1)
    let is_properties = env_file.ends_with(".properties");
    let lines: Vec<&str> = file_content.lines().collect();
    let mut new_lines: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let assignment = split_assignment(&env_file, line);
        let line_count = if assignment.is_some() {
            entry_line_count(&env_file, &lines, i)
        } else {
            1
        };
        let replacement = assignment.and_then(|(prefix, key, value_text)| {
            if is_public_key_name(key) || is_encrypted_value_text(value_text) {
                return None;
            }
            let encrypted = entries.get(key).filter(|v| v.starts_with("encrypted:"))?;
            Some(if is_properties {
                format!("{prefix}{key}={encrypted}")
            } else {
                format!("{prefix}{key}=\"{encrypted}\"")
            })
        });
        if let Some(new_line) = replacement {
            new_lines.push(new_line);
            is_changed = true;
            i += line_count;
        } else {
            // keep the whole entry, continuation lines of a multi-line value included
            let end = (i + line_count).min(lines.len());
            new_lines.extend(lines[i..end].iter().map(|l| l.to_string()));
            i = end;
        }
    }
    if is_stdout {
        let new_content = new_lines.join("\n");
        if is_sign_required {
            println!(
                "{}",
                add_or_replace_signature(&env_file, &new_content).unwrap()
            );
        } else {
            println!("{new_content}");
        }
        return;
    }
    // check content change, encrypt 丢失字段
    if !is_changed {
        if !is_sign_required {
            println!("{}", format!("✔ no changes ({env_file})").green());
        } else {
            let new_content = add_or_replace_signature(&env_file, &file_content).unwrap();
            fs::write(&env_file_path, new_content.as_bytes()).unwrap();
            println!("{}", format!("✔ sign added for ({env_file})").green());
        }
    } else {
        // use the exact public key name for this file, the same check as `update_env_file`, see review #4:
        // a `DOTENV_PUBLIC_KEY_PROD` entry in `.env` must not count as `.env`'s own `DOTENV_PUBLIC_KEY`
        let public_key_name = get_public_key_name_for_file(&env_file);
        let new_file_content = if content_has_key(&file_content, &public_key_name) {
            new_lines.join("\n")
        } else {
            // add the public key header to the env file if it does not exist
            construct_env_file_header(&public_key_name, &public_key, &None, &None)
                + "\n"
                + &new_lines.join("\n")
        };
        if is_sign_required {
            // signing must be the last step before writing: the content is not changed afterward
            let signed = add_or_replace_signature(&env_file, &new_file_content).unwrap();
            let signed = if signed.ends_with('\n') { signed } else { signed + "\n" };
            fs::write(&env_file_path, signed.as_bytes()).unwrap();
        } else {
            update_env_file(&env_file, &public_key, &new_file_content);
        }
        if is_sign_required {
            println!(
                "{}",
                format!("✔ {hint} encrypted and signed ({env_file})").green()
            );
        } else {
            println!("{}", format!("✔ {hint} encrypted ({env_file})").green());
        }
    }
}

/// Sign `env_file_content` with the private key that matches `env_file` (resolved by the file name,
/// not by the CLI `-p` profile), see review #6.
pub fn add_or_replace_signature(
    env_file: &str,
    env_file_content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key = get_private_key_for_file(env_file)?;
    sign_and_update_env_file_content(&private_key, env_file_content)
}

pub fn encrypt_env_entries(
    env_file: &str,
    public_key: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    if env_file.ends_with(".properties") {
        let encrypted_patterns = [
            "password",
            "pwd",
            "passwd",
            "secret",
            "private",
            "key",
            "token",
            "credential",
            "auth",
            "jwt",
            "jaas",
            "passphrase",
        ];
        let f = File::open(env_file)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader).read_into(|key, value| {
            if !value.starts_with("encrypted:") {
                if encrypted_patterns
                    .iter()
                    .any(|pattern| key.contains(pattern))
                {
                    let encrypted_text = encrypt_env_item(public_key, &value).unwrap();
                    entries.insert(key, encrypted_text);
                } else {
                    entries.insert(key, value);
                }
            } else {
                entries.insert(key, value);
            }
        })?;
    } else {
        for item in dotenvy::from_filename_iter(env_file)? {
            let (key, value) = &item?;
            // encrypt the value if it is not already encrypted or key contains _PLAIN
            if !key.contains("_PLAIN") && !value.starts_with("encrypted:") {
                let encrypted_text = encrypt_env_item(public_key, value)?;
                entries.insert(key.clone(), encrypted_text);
            } else {
                entries.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::crypt_util::{EcKeyPair, decrypt_env_item};

    #[test]
    fn test_encrypt_env_entries_dotenv() {
        let kp = EcKeyPair::generate();
        let (pk, sk) = (kp.get_pk_hex(), kp.get_sk_hex());
        let already = encrypt_env_item(&pk, "kept").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        fs::write(
            &env_file,
            format!("API_TOKEN=s3cr3t\nAPP_NAME=demo\nHOST_PLAIN=localhost\nOLD=\"{already}\"\n"),
        )
        .unwrap();
        let entries = encrypt_env_entries(env_file.to_str().unwrap(), &pk).unwrap();
        // every value of a .env file is encrypted, except `_PLAIN` keys
        for (key, plain) in [("API_TOKEN", "s3cr3t"), ("APP_NAME", "demo")] {
            let encrypted = &entries[key];
            assert!(encrypted.starts_with("encrypted:"), "{key}: {encrypted}");
            assert_eq!(decrypt_env_item(&sk, encrypted).unwrap(), plain);
        }
        assert_eq!(entries["HOST_PLAIN"], "localhost");
        // already encrypted values are kept as they are
        assert_eq!(entries["OLD"], already);
    }

    #[test]
    fn test_encrypt_env_entries_properties_only_sensitive_keys() {
        let kp = EcKeyPair::generate();
        let (pk, sk) = (kp.get_pk_hex(), kp.get_sk_hex());
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("application.properties");
        fs::write(
            &env_file,
            "server.port=8080\ndb.password=secret1\napi.token: token1\n",
        )
        .unwrap();
        let entries = encrypt_env_entries(env_file.to_str().unwrap(), &pk).unwrap();
        assert_eq!(entries["server.port"], "8080");
        assert_eq!(
            decrypt_env_item(&sk, &entries["db.password"]).unwrap(),
            "secret1"
        );
        assert_eq!(
            decrypt_env_item(&sk, &entries["api.token"]).unwrap(),
            "token1"
        );
    }

    #[test]
    fn test_encrypt_env_entries_missing_file() {
        let kp = EcKeyPair::generate();
        assert!(encrypt_env_entries("/nonexistent/dir/.env", &kp.get_pk_hex()).is_err());
    }
}
