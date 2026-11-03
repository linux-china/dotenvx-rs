use crate::commands::crypt_util::encrypt_env_item;
use crate::commands::model::sign_and_update_env_file_content;
use crate::commands::{
    KeyPatterns, compile_key_patterns, construct_env_file_header, content_has_key,
    entry_line_count, get_env_file_arg, get_or_create_public_key_for_file,
    get_private_key_for_file, get_public_key_name_for_file, is_encrypted_value_text,
    is_public_key_name, is_sensitive_key, split_assignment, update_env_file,
    write_public_key_to_file,
};
use clap::ArgMatches;
use colored_json::Paint;
use java_properties::PropertiesIter;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::fs::File;
use std::io::BufReader;

pub fn encrypt_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let env_keys = command_matches.get_many::<String>("keys");
    let is_stdout = command_matches.get_flag("stdout");
    let is_sign_required = command_matches.get_flag("sign");
    // validate the key patterns before touching any file or key
    let patterns: Option<KeyPatterns> =
        match env_keys.map(|keys| compile_key_patterns(keys, &env_file)) {
            Some(Ok(patterns)) => Some(patterns),
            Some(Err(e)) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            None => None,
        };
    let env_file_path = std::path::PathBuf::from(&env_file);
    if !env_file_path.exists() {
        // create default env file if it does not exist
        let public_key = get_or_create_public_key_for_file(&env_file).unwrap();
        println!("'{env_file}' does not exist, creating a new file with public key.");
        write_public_key_to_file(&env_file_path, &public_key).unwrap();
        return;
    }
    let file_content = fs::read_to_string(&env_file_path).unwrap();
    // resolve the public key only once for the whole command
    let public_key = get_or_create_public_key_for_file(&env_file).unwrap();
    let entries = match encrypt_env_entries(&env_file, &public_key) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Error: failed to parse {env_file}: {e}");
            std::process::exit(1);
        }
    };
    let mut hint = format!(".env file({env_file})");
    if patterns.is_some() {
        hint = format!("keys in .env file: {env_file}");
    }
    let (new_lines, is_changed) =
        encrypt_content(&env_file, &file_content, entries, patterns.as_ref());
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
            crate::commands::write_env_file(&env_file_path, new_content.as_bytes()).unwrap();
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
            let signed = if signed.ends_with('\n') {
                signed
            } else {
                signed + "\n"
            };
            crate::commands::write_env_file(&env_file_path, signed.as_bytes()).unwrap();
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

/// Replace every assignment of `file_content` whose value was encrypted by this run, keep every
/// other line verbatim (review #1). `entries` are the parsed entries in file order, duplicates
/// included: each occurrence of a key gets the encrypted text of its own value, not the last one
/// (review #15). Returns the new lines and whether anything changed.
fn encrypt_content(
    env_file: &str,
    file_content: &str,
    entries: Vec<(String, String)>,
    patterns: Option<&KeyPatterns>,
) -> (Vec<String>, bool) {
    let mut values: HashMap<String, VecDeque<String>> = HashMap::new();
    for (key, value) in entries {
        values.entry(key).or_default().push_back(value);
    }
    let is_properties = env_file.ends_with(".properties");
    let lines: Vec<&str> = file_content.lines().collect();
    let mut new_lines: Vec<String> = Vec::new();
    let mut is_changed = false;
    let mut i = 0;
    while i < lines.len() {
        let assignment = split_assignment(env_file, lines[i]);
        let line_count = if assignment.is_some() {
            entry_line_count(env_file, &lines, i)
        } else {
            1
        };
        let end = (i + line_count).min(lines.len());
        let replacement = assignment.and_then(|(prefix, key, value_text)| {
            // consume this occurrence's value even when the line is kept, so that later
            // occurrences of the same key stay aligned with the parser
            let encrypted = values.get_mut(key).and_then(VecDeque::pop_front)?;
            if is_public_key_name(key)
                || is_encrypted_value_text(value_text)
                || !encrypted.starts_with("encrypted:")
                || patterns.is_some_and(|ps| !ps.matches(key))
            {
                return None;
            }
            if is_properties {
                return Some(format!("{prefix}{key}={encrypted}"));
            }
            // keep the trailing inline comment, which may sit on the last line of a multi-line value
            let mut entry_value = value_text.to_string();
            for line in &lines[i + 1..end] {
                entry_value.push('\n');
                entry_value.push_str(line);
            }
            Some(match inline_comment(&entry_value) {
                Some(comment) => format!("{prefix}{key}=\"{encrypted}\" {comment}"),
                None => format!("{prefix}{key}=\"{encrypted}\""),
            })
        });
        if let Some(new_line) = replacement {
            new_lines.push(new_line);
            is_changed = true;
        } else {
            // keep the whole entry, continuation lines of a multi-line value included
            new_lines.extend(lines[i..end].iter().map(|l| l.to_string()));
        }
        i = end;
    }
    (new_lines, is_changed)
}

/// The trailing inline comment (`# note`) of a .env entry, `value_text` is the raw text after `=`.
pub(crate) fn inline_comment(value_text: &str) -> Option<&str> {
    let rest = match value_text.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let mut chars = value_text.char_indices().skip(1);
            let mut end = None;
            while let Some((idx, c)) = chars.next() {
                if c == '\\' && quote == '"' {
                    chars.next();
                } else if c == quote {
                    end = Some(idx + 1);
                    break;
                }
            }
            &value_text[end?..]
        }
        // an unquoted value ends at the first `#` that follows a whitespace
        _ => {
            let start = value_text
                .char_indices()
                .find(|&(idx, c)| c == '#' && value_text[..idx].ends_with(char::is_whitespace))?
                .0;
            &value_text[start..]
        }
    };
    let comment = rest.trim();
    comment.starts_with('#').then_some(comment)
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
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    // in file order, duplicated keys included (review #15)
    let mut entries: Vec<(String, String)> = Vec::new();
    if env_file.ends_with(".properties") {
        let f = File::open(env_file)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader).read_into(|key, value| {
            if !value.starts_with("encrypted:") {
                // same (case-insensitive) rule as `set`, `sync` and `doctor`, see review #24
                if is_sensitive_key(&key) {
                    let encrypted_text = encrypt_env_item(public_key, &value).unwrap();
                    entries.push((key, encrypted_text));
                } else {
                    entries.push((key, value));
                }
            } else {
                entries.push((key, value));
            }
        })?;
    } else {
        for item in dotenvy::from_filename_iter(env_file)? {
            let (key, value) = &item?;
            // encrypt the value if it is not already encrypted or key contains _PLAIN
            if !key.contains("_PLAIN") && !value.starts_with("encrypted:") {
                let encrypted_text = encrypt_env_item(public_key, value)?;
                entries.push((key.clone(), encrypted_text));
            } else {
                entries.push((key.clone(), value.clone()));
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
        let entries: HashMap<_, _> = encrypt_env_entries(env_file.to_str().unwrap(), &pk)
            .unwrap()
            .into_iter()
            .collect();
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
            "server.port=8080\ndb.password=secret1\napi.token: token1\nDB_PASSWORD=secret2\n",
        )
        .unwrap();
        let entries: HashMap<_, _> = encrypt_env_entries(env_file.to_str().unwrap(), &pk)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(entries["server.port"], "8080");
        assert_eq!(
            decrypt_env_item(&sk, &entries["db.password"]).unwrap(),
            "secret1"
        );
        assert_eq!(
            decrypt_env_item(&sk, &entries["api.token"]).unwrap(),
            "token1"
        );
        // upper-case keys are sensitive too (review #24)
        assert_eq!(
            decrypt_env_item(&sk, &entries["DB_PASSWORD"]).unwrap(),
            "secret2"
        );
    }

    fn decrypted_lines(sk: &str, lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|line| match line.split_once("\"encrypted:") {
                Some((head, rest)) => {
                    let (token, tail) = rest.split_once('"').unwrap();
                    let plain = decrypt_env_item(sk, &format!("encrypted:{token}")).unwrap();
                    format!("{head}<{plain}>{tail}")
                }
                None => line.clone(),
            })
            .collect()
    }

    #[test]
    fn test_encrypt_content_duplicated_keys_and_inline_comments() {
        let kp = EcKeyPair::generate();
        let (pk, sk) = (kp.get_pk_hex(), kp.get_sk_hex());
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        let content =
            "X=first\nX=second # note\nexport Q=\"a #b\" # quoted\nM=\"l1\nl2\" # multi\nX=third\n";
        fs::write(&env_file, content).unwrap();
        let env_file = env_file.to_str().unwrap();
        let entries = encrypt_env_entries(env_file, &pk).unwrap();
        let (lines, changed) = encrypt_content(env_file, content, entries, None);
        assert!(changed);
        assert_eq!(
            decrypted_lines(&sk, &lines),
            vec![
                "X=<first>",
                "X=<second> # note",
                "export Q=<a #b> # quoted",
                "M=<l1\nl2> # multi",
                "X=<third>",
            ]
        );
    }

    #[test]
    fn test_encrypt_content_key_filter_keeps_alignment() {
        let kp = EcKeyPair::generate();
        let (pk, sk) = (kp.get_pk_hex(), kp.get_sk_hex());
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        let already = encrypt_env_item(&pk, "old").unwrap();
        let content = format!("A=\"{already}\"\nB=1\nA=new\n");
        fs::write(&env_file, &content).unwrap();
        let env_file = env_file.to_str().unwrap();
        let entries = encrypt_env_entries(env_file, &pk).unwrap();
        let patterns = compile_key_patterns(&["A".to_string()], env_file).unwrap();
        let (lines, _) = encrypt_content(env_file, &content, entries, Some(&patterns));
        assert_eq!(
            decrypted_lines(&sk, &lines),
            vec!["A=<old>", "B=1", "A=<new>"]
        );
    }

    #[test]
    fn test_inline_comment() {
        assert_eq!(inline_comment("value # note"), Some("# note"));
        assert_eq!(inline_comment("value#not"), None);
        assert_eq!(inline_comment("\"a \\\" # b\" # c"), Some("# c"));
        assert_eq!(inline_comment("'a # b'"), None);
        assert_eq!(inline_comment("plain"), None);
    }

    #[test]
    fn test_encrypt_env_entries_missing_file() {
        let kp = EcKeyPair::generate();
        assert!(encrypt_env_entries("/nonexistent/dir/.env", &kp.get_pk_hex()).is_err());
    }
}
