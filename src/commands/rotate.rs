use crate::commands::crypt_util::{decrypt_env_item, encrypt_env_item, write_file_atomic};
use crate::commands::model::{KeyPair, get_signature, sign_and_update_env_file_content};
use crate::commands::{
    EcKeyPair, construct_env_file_header, dotenv_keys_files_for_env_file, get_env_file_arg,
    get_private_key_for_file, get_private_key_name_for_file, get_public_key_for_file,
    get_public_key_name_for_file, is_env_file_name, is_public_key_name, read_dotenv_file,
    read_public_key_from_file, trim_private_key, write_key_pair, write_private_key_to_file,
};
use clap::ArgMatches;
use colored_json::Paint;
use dotenvx_rs::common::get_profile_name_from_file;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// `dotenvx rotate`: generate a new key pair, re-encrypt every encrypted value with it and
/// replace the public key, all in memory; the file is then written once, atomically.
/// Plaintext values, comments and lines the parser doesn't recognize are kept verbatim.
pub fn rotate_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    if !Path::new(&env_file).is_file() {
        eprintln!("The specified .env file does not exist: {env_file}");
        std::process::exit(1);
    }
    if let Err(e) = rotate_env_file(&env_file, profile) {
        eprintln!("{}", format!("✘ failed to rotate {env_file}: {e}").red());
        std::process::exit(1);
    }
}

fn rotate_env_file(env_file: &str, profile: &Option<String>) -> Result<(), String> {
    let file_content = fs::read_to_string(env_file).map_err(|e| e.to_string())?;
    let is_properties = env_file.ends_with(".properties");
    // raw (still encrypted) entries from the real parser, used to confirm what the line scanner finds
    let raw_entries = read_raw_entries(env_file).map_err(|e| e.to_string())?;
    let has_encrypted = raw_entries.iter().any(|(_, v)| v.starts_with("encrypted:"));
    let old_public_key = get_public_key_for_file(env_file).ok();
    let old_private_key = if has_encrypted {
        Some(get_private_key_for_file(env_file).map_err(|e| e.to_string())?)
    } else {
        get_private_key_for_file(env_file).ok()
    };

    let pair = EcKeyPair::generate();
    let new_pk = pair.get_pk_hex();
    let new_sk = pair.get_sk_hex();
    let rotated = rotate_content(
        &file_content,
        is_properties,
        &raw_entries,
        old_private_key.as_deref(),
        old_public_key.as_deref(),
        &new_pk,
    )?;
    let mut new_content = if rotated.public_key_replaced {
        rotated.content
    } else {
        let header = construct_env_file_header(
            &get_public_key_name_for_file(env_file),
            &new_pk,
            &None,
            &None,
        );
        format!("{header}\n{}", rotated.content)
    };
    let was_signed = get_signature(&file_content).is_some();
    if was_signed {
        new_content =
            sign_and_update_env_file_content(&new_sk, &new_content).map_err(|e| e.to_string())?;
        if !new_content.ends_with('\n') {
            new_content.push('\n');
        }
    }

    let file_profile = get_profile_name_from_file(env_file).or_else(|| profile.clone());
    // the old key may still be used by other env files (shared `.env.keys`), make sure it stays
    // in the global key store before anything is replaced (review 2.6)
    if let Some(old_sk) = old_private_key.as_deref() {
        backup_old_key_pair(old_sk, &file_profile)
            .map_err(|e| format!("failed to back up the old private key, nothing changed: {e}"))?;
    }
    let key_pair = KeyPair::new(&new_pk, &new_sk, &file_profile);
    // persist the new private key before the file encrypted with it, so it can never be lost
    write_key_pair(&key_pair).map_err(|e| format!("failed to save the new private key: {e}"))?;
    write_file_atomic(env_file, new_content.as_bytes()).map_err(|e| e.to_string())?;

    let private_key_name = get_private_key_name_for_file(env_file);
    let (keys_files, held_old_key) =
        keys_files_to_update(env_file, &private_key_name, old_private_key.as_deref());
    // only a `.env.keys` that held the old key is overwritten, other files may depend on it
    if held_old_key && let Some(old_pk) = old_public_key.as_deref() {
        warn_shared_key_users(env_file, old_pk, &keys_files);
    }
    let mut updated_keys_files = 0;
    for keys_file in &keys_files {
        if let Err(e) = write_private_key_to_file(keys_file, &private_key_name, &key_pair, true) {
            // the new key is already in the global key store, decryption still works
            eprintln!(
                "{}",
                format!(
                    "Warning: failed to update {}: {e}, the new private key is in the global key store",
                    keys_file.display()
                )
                .yellow()
            );
        } else {
            updated_keys_files += 1;
        }
    }
    if updated_keys_files == 0 {
        println!(
            "{}",
            format!(
                "✔ private key({}...) saved to the global key store (.env.keys.json)",
                &new_sk[0..6]
            )
            .green()
        );
    }
    println!(
        "{}",
        format!(
            "✔ key pair rotated, {} encrypted value(s) re-encrypted with public key({}...) ({env_file})",
            rotated.reencrypted,
            &new_pk[0..8]
        )
        .green()
    );
    if was_signed {
        println!(
            "{}",
            format!("✔ signature updated with the new private key ({env_file})").green()
        );
    }
    if let Some(warning) = stale_private_key_warning(
        env_file,
        &private_key_name,
        updated_keys_files > 0,
        std::env::var(&private_key_name).is_ok(),
    ) {
        eprintln!("{}", warning.yellow());
    }
    Ok(())
}

/// Warn that copies of the old private key outside this machine's key files are now invalid.
/// Without an updated `.env.keys` the new key only lives in the local global key store, so
/// `DOTENV_PRIVATE_KEY*` secrets in CI/deployment must be replaced; the same applies when the
/// variable is set in the current environment (it still holds the old key).
fn stale_private_key_warning(
    env_file: &str,
    private_key_name: &str,
    keys_file_updated: bool,
    env_var_set: bool,
) -> Option<String> {
    if keys_file_updated && !env_var_set {
        return None;
    }
    let mut lines = Vec::new();
    if env_var_set {
        lines.push(format!(
            "⚠ {private_key_name} is set in the current environment and still holds the old private key, update or unset it"
        ));
    }
    if !keys_file_updated {
        lines.push(
            "⚠ no .env.keys was updated, the new private key only exists in this machine's global key store"
                .to_owned(),
        );
    }
    lines.push(format!(
        "⚠ the old private key can no longer decrypt {env_file}: update {private_key_name} wherever it is stored as a secret (CI, deployment, other machines)"
    ));
    lines.push(format!(
        "  run `dotenvx keypair -f {env_file}` to print the new private key"
    ));
    Some(lines.join("\n"))
}

/// Store the old key pair in the global key store (no-op if it's already there).
fn backup_old_key_pair(old_private_key: &str, profile: &Option<String>) -> Result<(), String> {
    let old_pair = EcKeyPair::from_secret_key(old_private_key).map_err(|e| e.to_string())?;
    let mut old_key_pair = KeyPair::new(&old_pair.get_pk_hex(), old_private_key, profile);
    old_key_pair.comment = Some("backup before rotate".to_owned());
    write_key_pair(&old_key_pair).map_err(|e| e.to_string())
}

/// Other env files that still declare `old_public_key`, searched in the directories of `env_file`
/// and of the `.env.keys` files being updated (and their sub directories, up to 2 levels).
fn find_shared_key_users(
    env_file: &str,
    old_public_key: &str,
    keys_files: &[PathBuf],
) -> Vec<PathBuf> {
    let env_path = Path::new(env_file);
    let canonical = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let self_path = canonical(env_path);
    let mut roots: Vec<PathBuf> = keys_files
        .iter()
        .filter_map(|f| f.parent().map(Path::to_path_buf))
        .collect();
    roots.push(env_path.parent().map(Path::to_path_buf).unwrap_or_default());
    let mut found: Vec<PathBuf> = Vec::new();
    for root in roots {
        let root = if root.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            root
        };
        let walker = walkdir::WalkDir::new(&root)
            .max_depth(3)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !e.file_type().is_dir()
                    || !matches!(
                        e.file_name().to_str(),
                        Some(".git" | "target" | "node_modules")
                    )
            });
        for entry in walker.filter_map(|e| e.ok()) {
            let Some(name) = entry.file_name().to_str() else {
                continue;
            };
            if !entry.file_type().is_file()
                || !(is_env_file_name(name) || name.ends_with(".properties"))
            {
                continue;
            }
            let path = canonical(entry.path());
            if path == self_path || found.contains(&path) {
                continue;
            }
            let Some(path_str) = path.to_str() else {
                continue;
            };
            if read_public_key_from_file(path_str)
                .ok()
                .flatten()
                .is_some_and(|pk| pk == old_public_key)
            {
                found.push(path);
            }
        }
    }
    found
}

fn warn_shared_key_users(env_file: &str, old_public_key: &str, keys_files: &[PathBuf]) {
    let users = find_shared_key_users(env_file, old_public_key, keys_files);
    if users.is_empty() {
        return;
    }
    let files = users
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "{}",
        format!(
            "Warning: the old key pair({}...) is still used by: {files}. The old private key is kept in the global key store (.env.keys.json) only, \
             other machines can not decrypt these files anymore, please rotate them too",
            &old_public_key[0..old_public_key.len().min(8)]
        )
        .yellow()
    );
}

/// Entries as written in the file, without decryption. Duplicated keys are all kept.
fn read_raw_entries(
    env_file: &str,
) -> Result<HashSet<(String, String)>, Box<dyn std::error::Error>> {
    if env_file.ends_with(".properties") {
        Ok(read_dotenv_file(env_file)?.into_iter().collect())
    } else {
        let mut entries = HashSet::new();
        for item in dotenvy::from_filename_iter(env_file)? {
            entries.insert(item?);
        }
        Ok(entries)
    }
}

/// `.env.keys` files that held the old private key of `env_file` (next to the file, then cwd).
/// If none holds it, the nearest `.env.keys` that has no such key name yet gets the new key;
/// an unrelated key with the same name is never overwritten.
/// The flag tells whether the returned files held the old private key.
fn keys_files_to_update(
    env_file: &str,
    private_key_name: &str,
    old_private_key: Option<&str>,
) -> (Vec<PathBuf>, bool) {
    let profile_name = get_profile_name_from_file(env_file);
    let candidates = dotenv_keys_files_for_env_file(env_file, &profile_name);
    let stored_key = |keys_file: &PathBuf| {
        read_dotenv_file(keys_file)
            .ok()
            .and_then(|entries| entries.get(private_key_name).cloned())
            .map(|v| trim_private_key(v.trim_matches('"').to_owned()))
    };
    let matched: Vec<PathBuf> = candidates
        .iter()
        .filter(|f| old_private_key.is_some() && stored_key(f).as_deref() == old_private_key)
        .cloned()
        .collect();
    if !matched.is_empty() {
        return (matched, true);
    }
    let fallback = candidates
        .into_iter()
        .find(|f| f.exists() && stored_key(f).is_none())
        .into_iter()
        .collect();
    (fallback, false)
}

struct RotatedContent {
    content: String,
    reencrypted: usize,
    public_key_replaced: bool,
}

/// Re-encrypt every `encrypted:` value in `content` with `new_public_key` and replace the old
/// public key, touching nothing else. A value is only rotated when the real parser agrees on
/// its key and value (`raw_entries`); an `encrypted:` value the scanner sees but the parser
/// doesn't confirm aborts the rotation instead of leaving undecryptable data behind.
fn rotate_content(
    content: &str,
    is_properties: bool,
    raw_entries: &HashSet<(String, String)>,
    old_private_key: Option<&str>,
    old_public_key: Option<&str>,
    new_public_key: &str,
) -> Result<RotatedContent, String> {
    let mut output = String::with_capacity(content.len());
    let mut reencrypted = 0;
    let mut public_key_replaced = false;
    for raw_line in content.split_inclusive('\n') {
        let (line, ending) = split_line_ending(raw_line);
        let Some((key, value_start)) = parse_assignment(line, is_properties) else {
            output.push_str(raw_line);
            continue;
        };
        let value = parse_value(&line[value_start..]);
        let new_token = if value.token.starts_with("encrypted:") {
            if !raw_entries.contains(&(key.to_owned(), value.token.to_owned())) {
                return Err(format!(
                    "can not parse the encrypted value of '{key}', nothing changed"
                ));
            }
            let private_key = old_private_key.ok_or("private key not found, nothing changed")?;
            let plain = decrypt_env_item(private_key, value.token)
                .map_err(|e| format!("failed to decrypt '{key}': {e}, nothing changed"))?;
            reencrypted += 1;
            Some(encrypt_env_item(new_public_key, &plain).map_err(|e| e.to_string())?)
        } else if is_public_key_name(key)
            && old_public_key.is_none_or(|pk| pk == value.token.trim())
        {
            public_key_replaced = true;
            Some(new_public_key.to_owned())
        } else {
            None
        };
        match new_token {
            Some(token) => {
                let token_start = value_start + value.token_offset;
                output.push_str(&line[..token_start]);
                output.push_str(&token);
                output.push_str(&line[token_start + value.token.len()..]);
                output.push_str(ending);
            }
            None => output.push_str(raw_line),
        }
    }
    let encrypted_total = raw_entries
        .iter()
        .filter(|(_, v)| v.starts_with("encrypted:"))
        .count();
    if reencrypted < encrypted_total {
        return Err(format!(
            "only {reencrypted} of {encrypted_total} encrypted values could be located in the file, nothing changed"
        ));
    }
    Ok(RotatedContent {
        content: output,
        reencrypted,
        public_key_replaced,
    })
}

fn split_line_ending(raw_line: &str) -> (&str, &str) {
    if let Some(line) = raw_line.strip_suffix("\r\n") {
        (line, "\r\n")
    } else if let Some(line) = raw_line.strip_suffix('\n') {
        (line, "\n")
    } else {
        (raw_line, "")
    }
}

/// Parse `[export ]KEY=value` (dotenv) or `key=value` / `key: value` / `key value` (properties).
/// Returns the key and the byte offset where the value starts, `None` for comments/blank lines.
fn parse_assignment(line: &str, is_properties: bool) -> Option<(&str, usize)> {
    let indent = line.len() - line.trim_start().len();
    let rest = &line[indent..];
    if rest.is_empty() || rest.starts_with('#') || (is_properties && rest.starts_with('!')) {
        return None;
    }
    let (key, after_key) = if is_properties {
        let end = rest
            .find(|c: char| c == '=' || c == ':' || c.is_whitespace())
            .unwrap_or(rest.len());
        let after = &rest[end..];
        let trimmed = after.trim_start();
        let after_sep = trimmed
            .strip_prefix(['=', ':'])
            .map(|s| s.trim_start())
            .unwrap_or(trimmed);
        (&rest[..end], indent + end + (after.len() - after_sep.len()))
    } else {
        let body = rest.strip_prefix("export ").unwrap_or(rest);
        let body_start = indent + (rest.len() - body.len());
        let eq = body.find('=')?;
        let after = &body[eq + 1..];
        let value_start = body_start + eq + 1 + (after.len() - after.trim_start().len());
        (body[..eq].trim(), value_start)
    };
    if key.is_empty() {
        return None;
    }
    Some((key, after_key))
}

struct Value<'a> {
    token: &'a str,
    /// offset of `token` inside the value text (1 when quoted)
    token_offset: usize,
}

/// The value token, without surrounding quotes and without a trailing inline comment.
fn parse_value(value_text: &str) -> Value<'_> {
    for quote in ['"', '\''] {
        if let Some(inner) = value_text.strip_prefix(quote)
            && let Some(end) = inner.find(quote)
        {
            return Value {
                token: &inner[..end],
                token_offset: 1,
            };
        }
    }
    let end = value_text
        .find(char::is_whitespace)
        .unwrap_or(value_text.len());
    Value {
        token: &value_text[..end],
        token_offset: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_of(content: &str) -> HashSet<(String, String)> {
        dotenvy::from_read_iter(content.as_bytes())
            .flatten()
            .collect()
    }

    #[test]
    fn test_stale_private_key_warning() {
        let key = "DOTENV_PRIVATE_KEY_PROD";
        assert!(stale_private_key_warning(".env.prod", key, true, false).is_none());

        let only_global = stale_private_key_warning(".env.prod", key, false, false).unwrap();
        assert!(only_global.contains("no .env.keys was updated"));
        assert!(only_global.contains("update DOTENV_PRIVATE_KEY_PROD"));
        assert!(only_global.contains("dotenvx keypair -f .env.prod"));
        assert!(!only_global.contains("current environment"));

        let env_var = stale_private_key_warning(".env.prod", key, true, true).unwrap();
        assert!(env_var.contains("set in the current environment"));
        assert!(!env_var.contains("no .env.keys was updated"));
    }

    #[test]
    fn test_rotate_content_keeps_lines_and_plain_values() {
        let old = EcKeyPair::generate();
        let new = EcKeyPair::generate();
        let enc = |v: &str| encrypt_env_item(&old.get_pk_hex(), v).unwrap();
        let content = format!(
            "# ---\n  # indented comment\nDOTENV_PUBLIC_KEY=\"{}\"\n\nexport TOKEN={}\nPLAIN=hello\nNAME_PLAIN=\"a\\\"b\"\nSECRET=\"{}\" # inline\n",
            old.get_pk_hex(),
            enc("tok"),
            enc("s3cret"),
        );
        let raw = raw_of(&content);
        let rotated = rotate_content(
            &content,
            false,
            &raw,
            Some(&old.get_sk_hex()),
            Some(&old.get_pk_hex()),
            &new.get_pk_hex(),
        )
        .unwrap();
        assert_eq!(rotated.reencrypted, 2);
        assert!(rotated.public_key_replaced);
        let out = rotated.content;
        assert!(out.contains("  # indented comment\n"));
        assert!(out.contains("PLAIN=hello\n"));
        assert!(out.contains("NAME_PLAIN=\"a\\\"b\"\n"));
        assert!(out.contains(" # inline\n"));
        assert!(out.contains(&format!("DOTENV_PUBLIC_KEY=\"{}\"\n", new.get_pk_hex())));
        assert!(!out.contains(&old.get_pk_hex()));
        assert_eq!(out.lines().count(), content.lines().count());
        let entries: std::collections::HashMap<String, String> = raw_of(&out).into_iter().collect();
        let dec = |k: &str| decrypt_env_item(&new.get_sk_hex(), &entries[k]).unwrap();
        assert_eq!(dec("TOKEN"), "tok");
        assert_eq!(dec("SECRET"), "s3cret");
        assert_eq!(entries["PLAIN"], "hello");
    }

    #[test]
    fn test_rotate_content_aborts_on_wrong_key() {
        let old = EcKeyPair::generate();
        let other = EcKeyPair::generate();
        let content = format!("A={}\n", encrypt_env_item(&old.get_pk_hex(), "x").unwrap());
        let result = rotate_content(
            &content,
            false,
            &raw_of(&content),
            Some(&other.get_sk_hex()),
            None,
            &other.get_pk_hex(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_content_properties() {
        let old = EcKeyPair::generate();
        let new = EcKeyPair::generate();
        let enc = encrypt_env_item(&old.get_pk_hex(), "pwd").unwrap();
        let content = format!(
            "dotenv.public.key={}\napp.name=demo\nserver.port: 8080\ndb.password: {enc}\n",
            old.get_pk_hex()
        );
        let raw: HashSet<(String, String)> = [
            ("dotenv.public.key".to_owned(), old.get_pk_hex()),
            ("app.name".to_owned(), "demo".to_owned()),
            ("server.port".to_owned(), "8080".to_owned()),
            ("db.password".to_owned(), enc.clone()),
        ]
        .into_iter()
        .collect();
        let rotated = rotate_content(
            &content,
            true,
            &raw,
            Some(&old.get_sk_hex()),
            Some(&old.get_pk_hex()),
            &new.get_pk_hex(),
        )
        .unwrap();
        assert_eq!(rotated.reencrypted, 1);
        let out = rotated.content;
        assert!(out.contains("app.name=demo\nserver.port: 8080\n"));
        assert!(out.contains(&format!("dotenv.public.key={}\n", new.get_pk_hex())));
        let line = out
            .lines()
            .find(|l| l.starts_with("db.password: "))
            .unwrap();
        let value = line.trim_start_matches("db.password: ");
        assert_eq!(decrypt_env_item(&new.get_sk_hex(), value).unwrap(), "pwd");
    }
}
