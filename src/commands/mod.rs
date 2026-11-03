use crate::commands::crypt_util::EcKeyPair;
use crate::commands::framework::detect_framework;
use crate::commands::model::{DotenvxKeyStore, KeyPair};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use csv::WriterBuilder;
use dotenvx_rs::common::{
    KEYS_FILE_NAME, find_env_file_path, get_dotenv_keys_file_path, get_profile_name_from_file,
    is_global_profile, trim_private_key,
};
use java_properties::PropertiesIter;
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::{env, fs, io};
use walkdir::DirEntry;

pub mod crypt_util;
pub mod decrypt;
pub mod del_cmd;
pub mod diff;
pub mod encrypt;
pub mod get_cmd;
pub mod init;
pub mod keypair;
pub mod list;
mod model;
pub mod rotate;
pub mod run;
pub mod set_cmd;
pub mod verify;

pub mod cloud;
pub mod completion;
pub mod doctor;
pub mod dotenvx_cloud;
pub mod framework;
pub mod link;
pub mod linter;
pub mod sync;

pub use dotenvx_rs::common::{get_dotenvx_home, get_private_key_name};

pub fn is_sensitive_key(key_name: &str) -> bool {
    let encrypted_patterns = [
        "password",
        "pwd",
        "passwd",
        "passphrase",
        "jwt",
        "auth",
        "secret",
        "private",
        "jaas",
        "key",
        "token",
        "credential",
    ];
    let key_name_lowercase = key_name.to_lowercase();
    for encrypted_pattern in encrypted_patterns {
        if key_name_lowercase.contains(encrypted_pattern) {
            return true;
        }
    }
    false
}

/// Private key of the public key in the global key store (falls back to the key store on a USB disk),
/// same lookup as the library.
pub fn find_private_key_from_home(public_key_hex: &str) -> Option<String> {
    dotenvx_rs::common::find_private_key_in_global_store(public_key_hex)
}

pub fn find_all_keys() -> HashMap<String, KeyPair> {
    if let Ok(key_store) = DotenvxKeyStore::load_global() {
        key_store.keys.clone()
    } else {
        HashMap::new()
    }
}

/// Restrict a sensitive file (private keys, decrypted plaintext, sealed key store)
/// to owner read/write only (0600) on Unix. No-op on other platforms.
pub fn restrict_file_permissions<P: AsRef<Path>>(path: P) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            eprintln!(
                "Warning: failed to set 0600 permissions on {}: {e}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Write a file holding secrets (private keys, decrypted plaintext) without ever exposing it
/// to other users, atomically: the content goes to a new 0600 `<path>.tmp`, is fsynced and then
/// renamed over `path`, so an interruption never leaves an empty or half-written file (see review #7).
pub fn write_private_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> io::Result<()> {
    crypt_util::write_file_atomic(path, bytes).map_err(io::Error::other)
}

/// Rewrite an env file (ciphertext, public keys, signatures) atomically, keeping the existing
/// file's permissions: an interruption never leaves an empty or half-written env file.
pub fn write_env_file<P: AsRef<Path>>(path: P, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    crypt_util::write_file_atomic_keep_mode(path, bytes.as_ref()).map_err(io::Error::other)
}

pub fn write_key_pair(key_pair: &KeyPair) -> anyhow::Result<()> {
    write_key_pairs(&vec![key_pair.clone()])
}

pub fn write_key_pairs(key_pairs: &Vec<KeyPair>) -> anyhow::Result<()> {
    DotenvxKeyStore::update_global(|key_store| {
        let mut is_changed = false;
        for key_pair in key_pairs {
            if !key_store.keys.contains_key(&key_pair.public_key) {
                is_changed = true;
                key_store
                    .keys
                    .insert(key_pair.public_key.clone(), key_pair.clone());
            }
        }
        Ok((is_changed, ()))
    })
}

/// Decrypt the sealed key store and merge its keys into $HOME/.dotenvx/.env.keys.json
pub fn merge_sealed_key_store(encrypted_file_path: &Path, password: &str) -> anyhow::Result<()> {
    let plain_bytes = crypt_util::decrypt_file_to_bytes(encrypted_file_path, password)?;
    let sealed_store = DotenvxKeyStore::from_json(&String::from_utf8(plain_bytes)?)?;
    DotenvxKeyStore::update_global(|key_store| {
        // always write: the json file may not exist yet after `--seal`
        key_store.merge(sealed_store);
        Ok((true, ()))
    })
}

/// Merge the content of a sealed `$HOME/.env.keys` into the current plaintext one.
///
/// `current` wins: it is kept verbatim, and every `KEY=value` line of `sealed` whose key is
/// not in `current` is appended. Returns the merged text and the keys present in both
/// with different values (the `current` value is kept for those).
pub fn merge_env_keys_text(current: &str, sealed: &str) -> (String, Vec<String>) {
    let current_entries: HashMap<String, String> = dotenvy::from_read_iter(current.as_bytes())
        .flatten()
        .collect();
    let mut merged = current.to_owned();
    let mut conflicts = Vec::new();
    for line in sealed.lines() {
        let Some((key, value)) = dotenvy::from_read_iter(line.as_bytes()).flatten().next() else {
            continue; // blank line or comment
        };
        match current_entries.get(&key) {
            Some(current_value) => {
                if current_value != &value && !conflicts.contains(&key) {
                    conflicts.push(key);
                }
            }
            None => {
                if !merged.is_empty() && !merged.ends_with('\n') {
                    merged.push('\n');
                }
                merged.push_str(line);
                merged.push('\n');
            }
        }
    }
    (merged, conflicts)
}

pub fn read_dotenv_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    let file_name = path.as_ref().file_name().and_then(|s| s.to_str()).unwrap();
    if file_name.ends_with(".properties") {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader).read_into(|key, value| {
            // trim double quote
            let new_value = if value.starts_with('"') && value.ends_with('"') {
                value[1..value.len() - 1].to_string()
            } else {
                value
            };
            entries.insert(key, new_value);
        })?;
    } else {
        for (key, value) in dotenvy::from_filename_iter(path)?.flatten() {
            entries.insert(key.clone(), value.clone());
        }
    }
    Ok(entries)
}

pub fn read_dotenv_url(
    file_url: &str,
    headers: Option<HashMap<String, String>>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    let body = read_content_from_dotenv_url(file_url, headers)?;
    let reader = io::Cursor::new(body.into_bytes());
    for (key, value) in dotenvy::from_read_iter(reader).flatten() {
        entries.insert(key.clone(), value.clone());
    }
    Ok(entries)
}

pub fn read_content_from_dotenv_url(
    file_url: &str,
    headers: Option<HashMap<String, String>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut request = http_agent().get(file_url);
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            request = request.header(key, value);
        }
    }
    let mut response = request.call()?;
    if response.status().is_success() {
        let body = response.body_mut().read_to_string()?;
        Ok(body)
    } else {
        Err(format!(
            "Failed to fetch dotenv file from URL: {}. Status: {}",
            file_url,
            response.status()
        )
        .into())
    }
}

/// HTTP agent with platform certificate verification; non-2xx status codes are returned as responses, not errors.
pub fn http_agent() -> ureq::Agent {
    let tls_config = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls_config)
        .http_status_as_error(false)
        .build()
        .new_agent()
}

/// Find the private key that matches the public key declared by (or resolved for) `env_file`.
/// See [`get_private_key_for_public_key`] for the lookup order.
pub fn get_private_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    let public_key = get_public_key_for_file(env_file)?;
    if public_key.is_empty() {
        return get_private_key(&profile_name);
    }
    get_private_key_for_public_key(&public_key, &profile_name, Some(env_file))
}

/// Find the private key for `public_key`, every candidate is verified against `public_key`.
/// The lookup is shared with the library (`run`, shims), see [`dotenvx_rs::common::find_private_key`] for the order.
pub fn get_private_key_for_public_key(
    public_key: &str,
    profile_name: &Option<String>,
    env_file: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(dotenvx_rs::common::find_private_key(
        Some(public_key),
        profile_name,
        env_file.map(Path::new),
    )?)
}

/// `.env.keys` files to search for `env_file`, see [`dotenvx_rs::common::dotenv_keys_files_for_env_file`].
fn dotenv_keys_files_for_env_file(env_file: &str, profile_name: &Option<String>) -> Vec<PathBuf> {
    dotenvx_rs::common::dotenv_keys_files_for_env_file(Path::new(env_file), profile_name)
}

/// read-only: find the private key for the profile, never generate a new one.
/// If the profile declares a public key (env file or `DOTENV_PUBLIC_KEY_{PROFILE}`), the private key
/// must match it, see [`get_private_key_for_public_key`].
pub fn get_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(public_key) = declared_public_key(profile_name)? {
        return get_private_key_for_public_key(&public_key, profile_name, None);
    }
    let env_key_name = get_private_key_name(profile_name);
    lookup_private_key(profile_name)?
        .ok_or_else(|| format!("Private key not found: {env_key_name}").into())
}

fn lookup_private_key(
    profile_name: &Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let env_key_name = get_private_key_name(profile_name);
    let dotenv_keys_file_path = get_dotenv_keys_file_path(profile_name);
    let key_entries = if let Some(file_path) = &dotenv_keys_file_path
        && file_path.exists()
    {
        read_dotenv_file(file_path)?
    } else {
        HashMap::new()
    };
    // same order as get_private_key_for_public_key: environment variable first, then .env.keys
    if let Ok(private_key) = env::var(&env_key_name) {
        return Ok(Some(trim_private_key(private_key)));
    }
    if let Some(private_key) = key_entries.get(&env_key_name) {
        return Ok(Some(trim_private_key(
            private_key.trim_matches('"').to_owned(),
        )));
    }
    Ok(None)
}

/// find the private key, and generate a new key pair and save it to .env.keys if not found.
/// Only call it from commands that create keys explicitly, such as encrypt/set.
pub fn get_or_create_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(private_key) = lookup_private_key(profile_name)? {
        return Ok(private_key);
    }
    let env_key_name = get_private_key_name(profile_name);
    let dotenv_keys_file_path = get_dotenv_keys_file_path(profile_name);
    // create a new private key if not found
    let key_pair = EcKeyPair::generate();
    let public_key_hex = key_pair.get_pk_hex();
    let private_key_hex = key_pair.get_sk_hex();
    let key_pair = KeyPair::new(&public_key_hex, &private_key_hex, profile_name);
    // `.env.keys` found from cwd upward may belong to a parent (another) project: only reuse the one in cwd,
    // otherwise create `.env.keys` in the current directory (review #16)
    let file_path = match dotenv_keys_file_path {
        Some(path) if is_global_profile(profile_name) || is_in_current_dir(&path) => path,
        _ => PathBuf::from(KEYS_FILE_NAME),
    };
    write_private_key_to_file(&file_path, &env_key_name, &key_pair, false)?;
    // make sure the new private key is persisted, otherwise values encrypted with it can never be decrypted
    match lookup_private_key(profile_name)? {
        Some(saved_key) if saved_key == private_key_hex => Ok(saved_key),
        _ => {
            Err(format!("Failed to save new private key {env_key_name} to {KEYS_FILE_NAME}").into())
        }
    }
}

fn is_in_current_dir(path: &Path) -> bool {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match (
        fs::canonicalize(parent),
        env::current_dir().and_then(fs::canonicalize),
    ) {
        (Ok(dir), Ok(cwd)) => dir == cwd,
        _ => false,
    }
}

/// read-only: never generate a new key pair
pub fn get_public_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    resolve_public_key_for_file(env_file, false)
}

/// generate a new key pair if no public/private key found.
/// Call it once per command and pass the public key down, see review #1.
pub fn get_or_create_public_key_for_file(
    env_file: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    resolve_public_key_for_file(env_file, true)
}

fn resolve_public_key_for_file(
    env_file: &str,
    create: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    // the public key declared by the file itself wins
    if let Some(public_key) = read_public_key_from_file(env_file)? {
        return Ok(public_key);
    }
    let profile_name = get_profile_name_from_file(env_file);
    resolve_public_key(&profile_name, create)
}

/// Read the public key declared in `env_file`: the key named after the file's profile first,
/// otherwise the only `DOTENV_PUBLIC_KEY*` / `dotenv.public.key*` entry. `None` if the file doesn't exist.
fn read_public_key_from_file(env_file: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let path = Path::new(env_file);
    if !path.is_file() {
        return Ok(None);
    }
    let entries = read_dotenv_file(path)?;
    let clean = |v: &String| v.trim().trim_matches('"').to_owned();
    if let Some(value) = entries.get(&get_public_key_name_for_file(env_file)) {
        let value = clean(value);
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    let mut public_keys: Vec<String> = entries
        .iter()
        .filter(|(k, _)| is_public_key_name(k))
        .map(|(_, v)| clean(v))
        .filter(|v| !v.is_empty())
        .collect();
    public_keys.sort();
    public_keys.dedup();
    if public_keys.len() == 1 {
        return Ok(public_keys.pop());
    }
    Ok(None)
}

/// read-only: never generate a new key pair
pub fn get_public_key(profile_name: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    resolve_public_key(profile_name, false)
}

/// The public key declared for the profile: in its env file (`.env.{profile}` from cwd upward,
/// or under the dotenvx home for `g_` profiles) or in `DOTENV_PUBLIC_KEY_{PROFILE}`. Never derived from a private key.
fn declared_public_key(
    profile_name: &Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let env_key_name = get_public_key_name(profile_name);
    let env_file_name = if let Some(name) = profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_string()
    };
    let dotenv_file_path = if is_global_profile(profile_name) {
        get_dotenvx_home().join(env_file_name)
    } else {
        find_env_file_path(&env::current_dir()?, &env_file_name)
            .unwrap_or_else(|| PathBuf::from(env_file_name))
    };
    let entries = if dotenv_file_path.exists() {
        read_dotenv_file(&dotenv_file_path)?
    } else {
        HashMap::new()
    };
    // read from env file
    if let Some(val) = entries.get(&env_key_name) {
        let val = val.trim().trim_matches('"');
        if !val.is_empty() {
            return Ok(Some(val.to_owned()));
        }
    }
    // read from environment variables
    if let Ok(public_key) = env::var(&env_key_name)
        && !public_key.trim().is_empty()
    {
        return Ok(Some(public_key.trim().to_owned()));
    }
    Ok(None)
}

fn resolve_public_key(
    profile_name: &Option<String>,
    create: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(public_key) = declared_public_key(profile_name)? {
        return Ok(public_key);
    }
    // get public key from the default private key
    let private_key_hex = if create {
        get_or_create_private_key(profile_name)?
    } else {
        get_private_key(profile_name)?
    };
    let kp = EcKeyPair::from_secret_key(&private_key_hex)
        .map_err(|e| format!("{e}: {}", get_private_key_name(profile_name)))?;
    Ok(kp.get_pk_hex())
}

pub fn get_public_key_from_text_file(file_path: &str) -> Option<String> {
    let content = fs::read_to_string(file_path).ok()?;
    if let Some(public_key) = find_public_key_in_lines(&content) {
        return Some(public_key);
    }
    // minified JSON: pretty print it so that the public key is on its own line
    if file_path.ends_with(".json") {
        let json_value = serde_json::from_str::<serde_json::Value>(&content).ok()?;
        let pretty_json_text = serde_json::to_string_pretty(&json_value).ok()?;
        return find_public_key_in_lines(&pretty_json_text);
    }
    None
}

/// Extract the public key from the first line like `DOTENV_PUBLIC_KEY=...` or `"dotenv.public.key": "..."`.
fn find_public_key_in_lines(content: &str) -> Option<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("dotenv.public.key") || line.contains("DOTENV_PUBLIC_KEY"))
        .find_map(|line| {
            let value = line.split(['=', ':', '：']).nth(1)?.trim();
            let value = value
                .split([',', ';', '}', ']', ')', ' ', '-', '_'])
                .next()?
                .trim()
                .trim_matches(['"', '\'']);
            (value.len() == 66).then(|| value.to_string())
        })
}

pub fn create_env_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
    pairs: Option<&str>,
    group: &Option<String>,
    name: &Option<String>,
) {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let mut env_pub_key_name = get_public_key_name(&profile_name);
    if file_name.ends_with(".properties") {
        env_pub_key_name = env_pub_key_name
            .to_lowercase()
            .replace('_', ".")
            .to_string();
    }
    let header_text = if file_name.ends_with(".properties") && env_file.as_ref().exists() {
        let mut app_name: Option<String> = name.clone();
        let mut app_group: Option<String> = group.clone();
        let f = File::open(&env_file).unwrap();
        let reader = BufReader::new(f);
        PropertiesIter::new(reader)
            .read_into(|key, value| {
                if key == "spring.application.name" {
                    app_name = Some(value);
                } else if key == "spring.application.group" {
                    app_group = Some(value);
                }
            })
            .unwrap();
        construct_env_file_header(&env_pub_key_name, public_key, &app_group, &app_name)
    } else {
        construct_env_file_header(&env_pub_key_name, public_key, group, name)
    };
    if env_file.as_ref().exists() {
        let file_content = fs::read_to_string(&env_file).unwrap();
        if !content_has_key(&file_content, &env_pub_key_name) {
            let file_content = format!("{}\n{}", header_text.trim(), file_content);
            write_env_file(&env_file, file_content.as_bytes()).unwrap();
            println!(
                "{}",
                format!("✔ A new public key added in {file_name} file").green()
            );
        }
    } else {
        let file_content = if let Some(pairs) = pairs {
            format!("{}\n{}", header_text.trim(), pairs)
        } else {
            header_text
        };
        // create parent directory if it does not exist
        if let Some(parent_dir) = env_file.as_ref().parent() {
            if !parent_dir.exists() {
                fs::create_dir_all(parent_dir).unwrap();
            }
        }
        if file_content.ends_with("\n") {
            write_env_file(&env_file, file_content.trim_start().as_bytes()).unwrap();
        } else {
            write_env_file(
                &env_file,
                format!("{}\n", file_content.trim_start()).as_bytes(),
            )
            .unwrap();
        }
    }
}

pub fn update_env_file<P: AsRef<Path>>(env_file: P, public_key: &str, content: &str) {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    if (file_name.ends_with(".properties") || file_name.starts_with(".env"))
        && !content_has_key(content, &get_public_key_name_for_file(file_name))
    {
        let header = construct_env_file_header(
            &get_public_key_name_for_file(file_name),
            public_key,
            &None,
            &None,
        );
        let new_content = format!("{}\n{}\n", header.trim(), content.trim());
        write_env_file(&env_file, new_content).unwrap();
    } else if content.ends_with("\n") {
        write_env_file(&env_file, content).unwrap();
    } else {
        write_env_file(&env_file, format!("{content}\n")).unwrap();
    }
}

/// 判断一行是否定义了 `key`（精确匹配 key 名，允许 `export ` 前缀和 `=` 两侧空白）
pub fn line_has_key(line: &str, key: &str) -> bool {
    let l = line.trim_start();
    let l = l.strip_prefix("export ").unwrap_or(l).trim_start();
    l.strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// 判断文本中是否有某一行定义了 `key`
pub fn content_has_key(content: &str, key: &str) -> bool {
    content.lines().any(|line| line_has_key(line, key))
}

/// 去掉 `.sh`/`.toml`（`# K=...`）和 `.xml`（`<!-- K=... -->`）中嵌入键值对时使用的注释前缀
fn strip_embedded_pair_prefix<'a>(env_file: &str, line: &'a str) -> &'a str {
    let trimmed = line.trim_start();
    if env_file.ends_with(".xml") {
        trimmed
            .strip_prefix("<!--")
            .map_or(trimmed, str::trim_start)
    } else if env_file.ends_with(".sh") || env_file.ends_with(".toml") {
        trimmed.strip_prefix('#').map_or(trimmed, str::trim_start)
    } else {
        trimmed
    }
}

/// 判断一行是否定义了 `key`（按文件类型）：
/// - `.properties`：`K=v`、`K: v`、`K v`
/// - `.sh`/`.toml`/`.xml`：带注释前缀的 `K=v`
/// - 其他（dotenv）：与 `line_has_key` 一致，允许 `export ` 前缀和 `=` 两侧空白
pub fn line_defines_key(env_file: &str, line: &str, key: &str) -> bool {
    let body = strip_embedded_pair_prefix(env_file, line);
    if env_file.ends_with(".properties") {
        body.strip_prefix(key).is_some_and(|rest| {
            rest.is_empty() || rest.starts_with(['=', ':']) || rest.starts_with(char::is_whitespace)
        })
    } else {
        line_has_key(body, key)
    }
}

/// 该行（去掉注释前缀后）是否以 `export ` 开头
pub fn line_has_export_prefix(env_file: &str, line: &str) -> bool {
    !env_file.ends_with(".properties")
        && strip_embedded_pair_prefix(env_file, line).starts_with("export ")
}

/// 从 `lines[start]` 开始的条目占用的行数：
/// - dotenv：值以 `"` 或 `'` 开头且当前行没有闭合时，一直到闭合引号所在行（找不到闭合则只算 1 行）
/// - `.properties`：行尾有奇数个 `\` 时是续行
///
/// `lines` 中的元素不应包含换行符。
pub fn entry_line_count(env_file: &str, lines: &[&str], start: usize) -> usize {
    if env_file.ends_with(".properties") {
        let ends_with_continuation = |line: &str| {
            line.trim_end_matches('\r')
                .chars()
                .rev()
                .take_while(|&c| c == '\\')
                .count()
                % 2
                == 1
        };
        let mut end = start;
        while end + 1 < lines.len() && ends_with_continuation(lines[end]) {
            end += 1;
        }
        return end - start + 1;
    }
    let body = strip_embedded_pair_prefix(env_file, lines[start]);
    let Some((_, value)) = body.split_once('=') else {
        return 1;
    };
    let value = value.trim_start();
    let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else {
        return 1;
    };
    // 返回 `s` 中是否出现了未转义的闭合引号（单引号内不处理转义）
    let has_closing_quote = |s: &str| {
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' && quote == '"' {
                chars.next();
            } else if c == quote {
                return true;
            }
        }
        false
    };
    if has_closing_quote(&value[1..]) {
        return 1;
    }
    (start + 1..lines.len())
        .find(|&i| has_closing_quote(lines[i]))
        .map_or(1, |end| end - start + 1)
}

/// Split an assignment line into `(prefix, key, value_text)`:
/// - `prefix`: indentation and the `export ` prefix (dotenv only), kept when the line is rewritten
/// - `value_text`: the raw text after the separator, leading whitespace removed
///
/// dotenv lines need `=`, `.properties` lines accept `=`, `:` or whitespace as separator.
/// Returns `None` for comments, empty lines and lines without a key.
pub fn split_assignment<'a>(env_file: &str, line: &'a str) -> Option<(&'a str, &'a str, &'a str)> {
    let is_properties = env_file.ends_with(".properties");
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') || (is_properties && trimmed.starts_with('!'))
    {
        return None;
    }
    let body = if is_properties {
        trimmed
    } else {
        trimmed
            .strip_prefix("export ")
            .map_or(trimmed, str::trim_start)
    };
    let prefix = &line[..line.len() - body.len()];
    let (key, rest) = if is_properties {
        let end = body.find(['=', ':', ' ', '\t'])?;
        let rest = body[end..].trim_start();
        let rest = rest.strip_prefix(['=', ':']).map_or(rest, str::trim_start);
        (&body[..end], rest)
    } else {
        let (key, rest) = body.split_once('=')?;
        (key.trim_end(), rest.trim_start())
    };
    if key.is_empty() {
        return None;
    }
    Some((prefix, key, rest))
}

/// Whether the raw value text of an assignment is an `encrypted:` value (optionally quoted).
pub fn is_encrypted_value_text(value_text: &str) -> bool {
    value_text
        .trim_start_matches(['"', '\''])
        .starts_with("encrypted:")
}

/// 删除 `content` 中所有定义了 `key` 的条目（包括多行值的续行），保留其余行的换行符。
/// 没有找到 `key` 时返回 `None`。
pub fn remove_key_entries(content: &str, env_file: &str, key: &str) -> Option<String> {
    let raw_lines: Vec<&str> = content.split_inclusive('\n').collect();
    let lines: Vec<&str> = raw_lines
        .iter()
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .collect();
    let mut new_content = String::with_capacity(content.len());
    let mut removed = false;
    let mut i = 0;
    while i < lines.len() {
        if line_defines_key(env_file, lines[i], key) {
            i += entry_line_count(env_file, &lines, i);
            removed = true;
        } else {
            new_content.push_str(raw_lines[i]);
            i += 1;
        }
    }
    removed.then_some(new_content)
}

/// 把 `content` 中所有定义了 `key` 的条目（包括多行值的续行）替换成 `make_pair(has_export)` 生成的行。
/// 没有找到 `key` 时返回 `None`。
pub fn replace_key_entries(
    content: &str,
    env_file: &str,
    key: &str,
    make_pair: impl Fn(bool) -> String,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut replaced = false;
    let mut i = 0;
    while i < lines.len() {
        if line_defines_key(env_file, lines[i], key) {
            new_lines.push(make_pair(line_has_export_prefix(env_file, lines[i])));
            i += entry_line_count(env_file, &lines, i);
            replaced = true;
        } else {
            new_lines.push(lines[i].to_string());
            i += 1;
        }
    }
    replaced.then(|| new_lines.join("\n"))
}

/// Escape a value for a `.properties` file so that `java.util.Properties` (and Spring) read back `value`.
///
/// Escapes `\`, newlines, tabs and leading spaces; no quotes are added.
pub fn properties_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let mut leading = true;
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str(r"\\"),
            '\n' => escaped.push_str(r"\n"),
            '\r' => escaped.push_str(r"\r"),
            '\t' => escaped.push_str(r"\t"),
            '\x0c' => escaped.push_str(r"\f"),
            ' ' if leading => escaped.push_str(r"\ "),
            _ => escaped.push(c),
        }
        if c != ' ' {
            leading = false;
        }
    }
    escaped
}

/// 文件原来带签名时，修改后重新签名；拿不到匹配的私钥时提示签名已失效。
pub fn resign_env_file_if_signed(env_file: &str, original_content: &str) {
    if model::get_signature(original_content).is_none() {
        return;
    }
    let result = fs::read_to_string(env_file)
        .map_err(|e| e.into())
        .and_then(|content| encrypt::add_or_replace_signature(env_file, &content))
        .and_then(|signed| {
            let signed = if signed.ends_with('\n') {
                signed
            } else {
                format!("{signed}\n")
            };
            write_env_file(env_file, signed).map_err(|e| e.into())
        });
    match result {
        Ok(()) => println!("{}", format!("✔ signature updated ({env_file})").green()),
        Err(e) => eprintln!(
            "{}",
            format!(
                "Warning: failed to re-sign {env_file}, the existing signature is now invalid: {e}"
            )
            .yellow()
        ),
    }
}

/// 读取 `key` 对应的值（去掉两侧引号），不存在返回 None
fn get_key_value_in_content(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .find(|line| line_has_key(line, key))
        .map(|line| {
            let value = line.split_once('=').map(|(_, v)| v).unwrap_or("").trim();
            value.trim_matches(|c| c == '"' || c == '\'').to_string()
        })
}

pub fn construct_env_file_header(
    env_pub_key_name: &str,
    public_key: &str,
    group: &Option<String>,
    name: &Option<String>,
) -> String {
    let env_file_uuid = uuid::Uuid::now_v7().to_string();
    format!(
        r#"
# ---
# uuid: {}
# name: {}
# group: {}
# ---
{}="{}"

# Environment variables. MAKE SURE to ENCRYPT them before committing to source control
"#,
        &env_file_uuid,
        name.clone().unwrap_or("project_name".to_owned()),
        group.clone().unwrap_or("group_name".to_owned()),
        &env_pub_key_name,
        public_key
    )
    .trim()
    .to_string()
}

pub fn write_public_key_to_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_short = public_key.chars().take(8).collect::<String>();
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let header_text = construct_env_file_header(&env_pub_key_name, public_key, &None, &None);
    // file does not exist, and we create it
    if !env_file.as_ref().exists() {
        write_env_file(&env_file, header_text.trim_start().as_bytes())?;
        println!(
            "{}",
            format!("✔ {file_name} file created with the public key").green()
        );
        return Ok(());
    } else {
        let env_file_content = fs::read_to_string(&env_file).unwrap();
        let existing_public_key = get_key_value_in_content(&env_file_content, &env_pub_key_name);
        if existing_public_key.is_none() {
            let file_content = format!("{}\n{}", header_text.trim(), env_file_content);
            write_env_file(&env_file, file_content.as_bytes())?;
            println!("{}", format!("✔ public key added in {file_name}").green());
        } else if existing_public_key.as_deref() != Some(public_key) {
            // update existing public key
            let mut new_content = String::new();
            for line in env_file_content.lines() {
                if line_has_key(line, &env_pub_key_name) {
                    new_content.push_str(&format!("{env_pub_key_name}=\"{public_key}\"\n"));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            write_env_file(&env_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ public key({public_key_short}...) updated in {file_name}").green()
            );
        } else {
            println!(
                "{}",
                format!("✔ public key({public_key_short}...) already exists in {file_name}")
                    .green()
            );
        }
    }
    Ok(())
}

/// Whether `env_keys_file` already holds a private key named `private_key_name`.
pub fn private_key_exists_in_file<P: AsRef<Path>>(
    env_keys_file: P,
    private_key_name: &str,
) -> bool {
    fs::read_to_string(env_keys_file)
        .ok()
        .and_then(|content| get_key_value_in_content(&content, private_key_name))
        .is_some_and(|value| !value.is_empty())
}

/// Write the private key to `.env.keys` and the global key store.
///
/// An existing private key with the same name but a different value is only replaced when
/// `overwrite` is true (explicit commands such as `rotate`), and the old key pair is backed up
/// to the global key store first. Otherwise an error is returned (review #1).
pub fn write_private_key_to_file<P: AsRef<Path>>(
    env_keys_file: P,
    private_key_name: &str,
    key_pair: &KeyPair,
    overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys_file_uuid = uuid::Uuid::now_v7().to_string();
    let private_key_value = &key_pair.private_key;
    let private_key_short = private_key_value.chars().take(6).collect::<String>();
    let file_name = env_keys_file
        .as_ref()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    // file does not exist, and we create it
    if !env_keys_file.as_ref().exists() {
        let file_content = format!(
            r#"
# ---
# uuid: {keys_file_uuid}
# name: {}
# group: {}
# ---

#  Private decryption keys. DO NOT commit to source control
{}="{}"
"#,
            &key_pair.name.clone().unwrap_or("project_name".to_string()),
            key_pair.group.clone().unwrap_or("group_name".to_string()),
            private_key_name,
            private_key_value
        );
        write_private_file(&env_keys_file, file_content.trim_start().as_bytes())?;

        println!(
            "{}",
            format!("✔ {file_name} file created with the private key({private_key_short}...)")
                .green()
        );
        // update the ignore files next to the keys file (e.g. `$HOME` for `g_` profiles),
        // not the current directory (review #26)
        let keys_dir = env_keys_file
            .as_ref()
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        append_to_ignores(keys_dir, file_name);
    } else {
        let env_keys_content = fs::read_to_string(&env_keys_file).unwrap();
        let existing_private_key = get_key_value_in_content(&env_keys_content, private_key_name);
        // no key in the file, we add it
        if existing_private_key.is_none() {
            let new_content = format!(
                "{}\n{}=\"{}\"\n",
                env_keys_content.trim(),
                private_key_name,
                private_key_value
            );
            write_private_file(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) added in {file_name}").green()
            );
        } else if existing_private_key.as_deref() != Some(private_key_value.as_str()) {
            if !overwrite {
                return Err(format!(
                    "{private_key_name} already exists in {} with a different value, refusing to overwrite it",
                    env_keys_file.as_ref().display()
                )
                .into());
            }
            // back up the old key pair to the global key store before overwriting it
            let old_private_key = existing_private_key.unwrap_or_default();
            let old_pair = EcKeyPair::from_secret_key(&old_private_key).map_err(|e| {
                format!("invalid existing {private_key_name}, refusing to overwrite it: {e}")
            })?;
            let mut old_key_pair =
                KeyPair::new(&old_pair.get_pk_hex(), &old_private_key, &key_pair.profile);
            old_key_pair.comment = Some(format!("backup of {private_key_name} before overwrite"));
            write_key_pair(&old_key_pair)
                .map_err(|e| format!("failed to back up the old {private_key_name}: {e}"))?;
            // update existing private key
            let mut new_content = String::new();
            for line in env_keys_content.lines() {
                if line_has_key(line, private_key_name) {
                    new_content.push_str(&format!("{private_key_name}=\"{private_key_value}\"\n"));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            if let Some(parent_dir) = env_keys_file.as_ref().parent() {
                if !parent_dir.exists() {
                    fs::create_dir_all(parent_dir).unwrap();
                }
            }
            write_private_file(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) updated in {file_name}").green()
            );
        } else {
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) already exists in {file_name}")
                    .green()
            );
        }
    }
    // .env.keys holds plaintext private keys, restrict to owner-only on Unix
    restrict_file_permissions(&env_keys_file);
    // write the key pairs to global
    write_key_pair(key_pair)?;
    Ok(())
}

pub fn get_env_file_arg(command_matches: &ArgMatches, profile: &Option<String>) -> String {
    // `try_get_one`: the global command (`dotenvx -c ...`) has no `env-file` arg, see review #13
    let env_file_arg = command_matches
        .try_get_one::<String>("env-file")
        .ok()
        .flatten();
    // specified .env file argument takes precedence
    if let Some(env_file) = env_file_arg {
        return env_file.clone();
    }
    // load env file by profile
    let dotenv_file = if let Some(profile_name) = profile {
        if profile_name.starts_with("g_") {
            get_dotenvx_home()
                .join(format!(".env.{profile_name}"))
                .display()
                .to_string()
        } else {
            format!(".env.{profile_name}")
        }
    } else {
        ".env".to_string()
    };
    // if the file does not exist in the current dir, we try to detect it
    if !Path::new(&dotenv_file).exists() {
        // detect other files
        let properties_file = if let Some(profile_name) = profile {
            format!("application-{profile_name}.properties")
        } else {
            "application.properties".to_string()
        };
        if Path::new(&properties_file).exists() {
            return properties_file;
        }
        // detect framework
        if let Some(framework) = detect_framework() {
            if framework == "spring-boot" {
                let properties_file = if let Some(profile_name) = profile {
                    format!("src/main/resources/application-{profile_name}.properties")
                } else {
                    "src/main/resources/application.properties".to_string()
                };
                if Path::new(&properties_file).exists() {
                    return properties_file;
                }
            } else if framework == "gofr" {
                let env_file = if let Some(profile_name) = profile {
                    format!("configs/.env.{profile_name}")
                } else {
                    "configs/.env".to_string()
                };
                if Path::new(&env_file).exists() {
                    return env_file;
                }
            }
        }
    }
    dotenv_file
}

pub fn get_public_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    }
}

pub fn is_public_key_name(key: &str) -> bool {
    key.starts_with("DOTENV_PUBLIC_KEY") || key.starts_with("dotenv.public.key")
}

pub fn is_public_key_included(file_content: &str) -> bool {
    file_content.contains("DOTENV_PUBLIC_KEY") || file_content.contains("dotenv.public.key")
}

pub fn get_public_key_name_for_file(env_file: &str) -> String {
    let public_key_name = if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    };
    if env_file.ends_with(".properties") {
        public_key_name.to_lowercase().replace('_', ".")
    } else {
        public_key_name
    }
}

pub fn get_private_key_name_for_file(env_file: &str) -> String {
    if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
}

pub fn adjust_env_key(key: &str, env_file: &str) -> String {
    if !env_file.contains(".properties") {
        key.replace(['-', '.'], "_").to_uppercase()
    } else {
        key.to_string()
    }
}
/// The `--keys` glob patterns given on the command line, see [`compile_key_patterns`].
#[derive(Debug)]
pub struct KeyPatterns {
    patterns: Vec<glob::Pattern>,
    options: glob::MatchOptions,
}

impl KeyPatterns {
    /// Whether `key` matches any of the patterns.
    ///
    /// `.env` keys are matched case-insensitively (the patterns are upper-cased by
    /// [`adjust_env_key`], but the keys in the file may be lower-case), `.properties` keys
    /// case-sensitively, see review #24.
    pub fn matches(&self, key: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches_with(key, self.options))
    }
}

/// Compile the `--keys` glob patterns given on the command line.
///
/// Each key is normalized with [`adjust_env_key`] first; an invalid glob (e.g. `[`)
/// is reported as an error instead of panicking.
pub fn compile_key_patterns<'a>(
    keys: impl IntoIterator<Item = &'a String>,
    env_file: &str,
) -> Result<KeyPatterns, String> {
    let patterns = keys
        .into_iter()
        .map(|key| {
            let adjusted = adjust_env_key(key, env_file);
            glob::Pattern::new(&adjusted)
                .map_err(|e| format!("invalid key pattern '{key}': {}", e.msg))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let options = glob::MatchOptions {
        case_sensitive: env_file.contains(".properties"),
        ..glob::MatchOptions::new()
    };
    Ok(KeyPatterns { patterns, options })
}
/// Quote a value for a POSIX shell `export K=...` line.
///
/// The whole value is wrapped in single quotes, so nothing inside (`$`, `` ` ``, `"`, `\`,
/// newlines) is interpreted by the shell; an embedded `'` is written as `'\''`.
pub fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Quote a value as a double-quoted `.env` value that dotenvy parses back to `value` unchanged.
///
/// Escapes `\`, `"`, `$` (to prevent variable substitution) and newlines.
pub fn dotenv_double_quote(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str(r#"\""#),
            '$' => escaped.push_str(r"\$"),
            '\n' => escaped.push_str(r"\n"),
            _ => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

/// Return the ignore file content with `file_name` appended as its own line, or `None` if a line
/// already equals `file_name` exactly (so `foo.env.keys` does not count as `.env.keys`, and a last
/// line without trailing newline is still detected).
fn append_ignore_entry(content: &str, file_name: &str) -> Option<String> {
    if content.lines().any(|line| line.trim() == file_name) {
        return None;
    }
    let mut new_content = content.to_owned();
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(file_name);
    new_content.push('\n');
    Some(new_content)
}

/// Add `file_name` to the `.gitignore`/`.dockerignore`/`.aiignore` files in `dir`.
///
/// A `.gitignore` is created only when `dir` is a git work tree root (`dir/.git` exists).
/// Failures are reported as warnings and never abort the caller (review #26).
pub fn append_to_ignores(dir: &Path, file_name: &str) {
    for ignore_file in [".gitignore", ".dockerignore", ".aiignore"] {
        let path = dir.join(ignore_file);
        let content = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("⚠ failed to read {}: {e}", path.display()).yellow()
                    );
                    continue;
                }
            }
        } else if ignore_file == ".gitignore" && dir.join(".git").exists() {
            String::new()
        } else {
            continue;
        };
        match append_ignore_entry(&content, file_name) {
            Some(new_content) => match fs::write(&path, new_content) {
                Ok(()) => println!(
                    "{}",
                    format!("✔ {file_name} added to {}", path.display()).green()
                ),
                Err(e) => eprintln!(
                    "{}",
                    format!("⚠ failed to add {file_name} to {}: {e}", path.display()).yellow()
                ),
            },
            None => println!(
                "{}",
                format!("✔ {file_name} already exists in {}", path.display()).green()
            ),
        }
    }
}

/// Whether `file_name` is a dotenv file (`.env` or `.env.<profile>`), excluding key stores
/// (`.env.keys`, `.env.keys.json`, `.env.keys.aes`, ...), `.env.vault`, and encrypted, lock,
/// temporary or backup files.
fn is_env_file_name(file_name: &str) -> bool {
    const EXCLUDED_SUFFIXES: [&str; 4] = [".aes", ".lock", ".tmp", ".bak"];
    if file_name == ".env" {
        return true;
    }
    file_name.starts_with(".env.")
        && !file_name.starts_with(".env.keys")
        && file_name != ".env.vault"
        && !EXCLUDED_SUFFIXES
            .iter()
            .any(|suffix| file_name.ends_with(suffix))
}

pub fn list_env_files<P: AsRef<Path>>(
    root: P,
    max_depth: usize,
    profile: &Option<String>,
) -> Vec<DirEntry> {
    walkdir::WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.file_name().to_str().is_some_and(is_env_file_name))
        .filter(|e| {
            // filter by profile if provided
            let file_name = e.file_name().to_str().unwrap_or_default();
            if let Some(profile_name) = profile {
                let env_file_name = format!(".env.{profile_name}");
                file_name == &env_file_name
            } else {
                true
            }
        })
        .collect()
}

pub fn std_output(entries: &HashMap<String, String>, format: &Option<&String>) {
    if let Some(fmt) = format {
        if *fmt == "json" {
            let json_value = json!(entries);
            println!("{}", to_colored_json_auto(&json_value).unwrap());
        } else if *fmt == "shell" {
            for (key, value) in entries {
                println!("export {key}={}", shell_single_quote(value));
            }
        } else if *fmt == "csv" {
            let mut wtr = WriterBuilder::new()
                .delimiter(b',') // Use semicolon as delimiter
                .terminator(csv::Terminator::CRLF) // Use CRLF for line endings
                .from_writer(io::stdout());
            wtr.write_record(["key", "value"]).unwrap();
            for (key, value) in entries {
                wtr.write_record([key, value]).unwrap();
            }
            wtr.flush().unwrap();
        } else if *fmt == "raw" {
            for value in entries.values() {
                println!("{value}");
            }
        } else {
            for (key, value) in entries {
                println!("{key}={}", dotenv_double_quote(value));
            }
        }
    }
}

pub fn is_remote_env_file(env_file: &str) -> bool {
    env_file.starts_with("http://") || env_file.starts_with("https://")
}

pub fn is_valid_env_key(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Helpers shared by the unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;

    /// The global store directory, if `DOTENVX_DIR` points somewhere other than the real
    /// `$HOME/.dotenvx`. Tests that write the global key store must skip otherwise
    /// (see AGENTS.md: run them with `DOTENVX_DIR=$HOME/.dotenvx2`).
    pub(crate) fn isolated_dotenvx_dir() -> Option<PathBuf> {
        let Some(dir) = std::env::var_os("DOTENVX_DIR").map(PathBuf::from) else {
            eprintln!("skip: DOTENVX_DIR not set");
            return None;
        };
        let real = dirs::home_dir()?.join(".dotenvx");
        let same = |a: &PathBuf, b: &PathBuf| {
            a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
        };
        if same(&dir, &real) {
            eprintln!(
                "skip: DOTENVX_DIR points to the real global store {}",
                real.display()
            );
            return None;
        }
        Some(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_key_patterns() {
        let keys = vec!["db-*".to_string(), "API_KEY".to_string()];
        let patterns = compile_key_patterns(&keys, ".env").unwrap();
        assert!(patterns.matches("DB_HOST"));
        assert!(patterns.matches("API_KEY"));
        assert!(!patterns.matches("APP_NAME"));
        let invalid = vec!["[".to_string()];
        let err = compile_key_patterns(&invalid, ".env").unwrap_err();
        assert!(err.contains("invalid key pattern '['"), "{err}");
    }

    #[test]
    fn test_public_and_private_key_from_file_in_sub_dir() {
        let dir =
            std::env::temp_dir().join(format!("dotenvx_file_key_test_{}", uuid::Uuid::now_v7()));
        let sub_dir = dir.join("sub").join("dir");
        fs::create_dir_all(&sub_dir).unwrap();
        let kp = EcKeyPair::generate();
        let other = EcKeyPair::generate();
        let env_file = sub_dir.join(".env.prod");
        fs::write(
            &env_file,
            format!("DOTENV_PUBLIC_KEY_PROD=\"{}\"\nA=1\n", kp.get_pk_hex()),
        )
        .unwrap();
        // the key for the profile lives in the .env.keys next to the file, a stale default key is ignored
        fs::write(
            sub_dir.join(KEYS_FILE_NAME),
            format!(
                "DOTENV_PRIVATE_KEY={}\nDOTENV_PRIVATE_KEY_PROD={}\n",
                other.get_sk_hex(),
                kp.get_sk_hex()
            ),
        )
        .unwrap();
        let env_file = env_file.to_str().unwrap();
        assert_eq!(get_public_key_for_file(env_file).unwrap(), kp.get_pk_hex());
        assert_eq!(get_private_key_for_file(env_file).unwrap(), kp.get_sk_hex());
        // a file name without profile: its own declared key is used
        let app_env = sub_dir.join("app.env");
        fs::write(
            &app_env,
            format!("DOTENV_PUBLIC_KEY_PROD={}\n", kp.get_pk_hex()),
        )
        .unwrap();
        assert_eq!(
            get_public_key_for_file(app_env.to_str().unwrap()).unwrap(),
            kp.get_pk_hex()
        );
        // properties file
        let props = sub_dir.join("application-prod.properties");
        fs::write(
            &props,
            format!("dotenv.public.key.prod={}\na=1\n", kp.get_pk_hex()),
        )
        .unwrap();
        assert_eq!(
            get_public_key_for_file(props.to_str().unwrap()).unwrap(),
            kp.get_pk_hex()
        );
        // a private key that doesn't match the public key is rejected
        fs::write(
            sub_dir.join(KEYS_FILE_NAME),
            format!("DOTENV_PRIVATE_KEY_PROD={}\n", other.get_sk_hex()),
        )
        .unwrap();
        assert!(get_private_key_for_file(env_file).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_private_key_lookup_order_and_verification() {
        let dir =
            std::env::temp_dir().join(format!("dotenvx_lookup_test_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let kp = EcKeyPair::generate();
        let other = EcKeyPair::generate();
        // a profile name unique to this test, so the env var doesn't leak into other tests
        let profile = format!("t{}", uuid::Uuid::now_v7().simple());
        let profile_name = Some(profile.clone());
        let key_name = get_private_key_name(&profile_name);
        let env_file = dir.join(format!(".env.{profile}"));
        fs::write(&env_file, "A=1\n").unwrap();
        fs::write(
            dir.join(KEYS_FILE_NAME),
            format!("{key_name}={}\n", other.get_sk_hex()),
        )
        .unwrap();
        let env_file = env_file.to_str().unwrap();
        // .env.keys holds a mismatched key: rejected
        assert!(
            get_private_key_for_public_key(&kp.get_pk_hex(), &profile_name, Some(env_file))
                .is_err()
        );
        // a mismatched env var is skipped as well, the matching .env.keys entry is used
        unsafe { env::set_var(&key_name, other.get_sk_hex()) };
        fs::write(
            dir.join(KEYS_FILE_NAME),
            format!("{key_name}={}\n", kp.get_sk_hex()),
        )
        .unwrap();
        assert_eq!(
            get_private_key_for_public_key(&kp.get_pk_hex(), &profile_name, Some(env_file))
                .unwrap(),
            kp.get_sk_hex()
        );
        // the environment variable comes first when both match
        assert_eq!(
            get_private_key_for_public_key(&other.get_pk_hex(), &profile_name, Some(env_file))
                .unwrap(),
            other.get_sk_hex()
        );
        // unverified lookup: environment variable first, same order as the verified lookup
        assert_eq!(
            lookup_private_key(&profile_name).unwrap(),
            Some(other.get_sk_hex())
        );
        // a declared public key makes get_private_key verify: the env var doesn't match it
        let pk_name = get_public_key_name(&profile_name);
        unsafe { env::set_var(&pk_name, kp.get_pk_hex()) };
        assert!(get_private_key(&profile_name).is_err());
        unsafe { env::set_var(&key_name, kp.get_sk_hex()) };
        assert_eq!(get_private_key(&profile_name).unwrap(), kp.get_sk_hex());
        unsafe {
            env::remove_var(&key_name);
            env::remove_var(&pk_name);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_is_in_current_dir() {
        assert!(is_in_current_dir(Path::new(KEYS_FILE_NAME)));
        let cwd = env::current_dir().unwrap();
        assert!(is_in_current_dir(&cwd.join(KEYS_FILE_NAME)));
        if let Some(parent) = cwd.parent() {
            assert!(!is_in_current_dir(&parent.join(KEYS_FILE_NAME)));
        }
    }

    #[test]
    fn test_public_key_for_missing_properties_file_no_panic() {
        let file = std::env::temp_dir()
            .join(format!("dotenvx_missing_{}", uuid::Uuid::now_v7()))
            .join("application.properties");
        let _ = get_public_key_for_file(file.to_str().unwrap());
    }

    #[test]
    fn test_line_has_key_exact_match() {
        assert!(line_has_key(
            "DOTENV_PUBLIC_KEY=\"abc\"",
            "DOTENV_PUBLIC_KEY"
        ));
        assert!(line_has_key("  export KEY = 1", "KEY"));
        assert!(!line_has_key(
            "DOTENV_PUBLIC_KEY_PROD=\"abc\"",
            "DOTENV_PUBLIC_KEY"
        ));
        assert!(!line_has_key("MY_KEY=1", "KEY"));
        assert!(!line_has_key("# KEY=1", "KEY"));
        assert!(content_has_key("A=1\nKEY=2\n", "KEY"));
        assert!(!content_has_key("MY_KEY=1\nKEY_2=2\n", "KEY"));
    }

    #[test]
    fn test_write_public_key_keeps_profile_key() {
        let dir = std::env::temp_dir().join(format!("dotenvx_pk_test_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join(".env");
        fs::write(&env_file, "DOTENV_PUBLIC_KEY_PROD=\"prod_pub\"\nA=1\n").unwrap();
        write_public_key_to_file(&env_file, "default_pub").unwrap();
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(content.contains("DOTENV_PUBLIC_KEY_PROD=\"prod_pub\""));
        assert!(content.contains("DOTENV_PUBLIC_KEY=\"default_pub\""));
        // update the default key, profile key stays
        write_public_key_to_file(&env_file, "default_pub2").unwrap();
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(content.contains("DOTENV_PUBLIC_KEY_PROD=\"prod_pub\""));
        assert!(content.contains("DOTENV_PUBLIC_KEY=\"default_pub2\""));
        assert!(!content.contains("default_pub\""));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_write_private_key_with_profile_key_present() {
        // write_private_key_to_file also writes the global key store, only run when isolated
        if test_support::isolated_dotenvx_dir().is_none() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("dotenvx_sk_test_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let keys_file = dir.join(".env.keys");
        fs::write(&keys_file, "DOTENV_PRIVATE_KEY_PROD=\"prod_sk\"\n").unwrap();
        let mut key_pair = KeyPair::new("default_pub_test", "default_sk_test", &None);
        key_pair.path = Some(dir.to_string_lossy().to_string());
        write_private_key_to_file(&keys_file, "DOTENV_PRIVATE_KEY", &key_pair, false).unwrap();
        let content = fs::read_to_string(&keys_file).unwrap();
        assert!(content.contains("DOTENV_PRIVATE_KEY_PROD=\"prod_sk\""));
        assert!(content.contains("DOTENV_PRIVATE_KEY=\"default_sk_test\""));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_write_private_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        // new file: created as 0600 directly
        let new_file = dir.join(format!("dotenvx_private_new_{}", uuid::Uuid::now_v7()));
        write_private_file(&new_file, b"DOTENV_PRIVATE_KEY=secret").unwrap();
        let new_mode = fs::metadata(&new_file).unwrap().permissions().mode() & 0o777;
        // existing world-readable file: restricted, content replaced
        let old_file = dir.join(format!("dotenvx_private_old_{}", uuid::Uuid::now_v7()));
        fs::write(&old_file, b"old").unwrap();
        fs::set_permissions(&old_file, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&old_file, b"new").unwrap();
        let old_mode = fs::metadata(&old_file).unwrap().permissions().mode() & 0o777;
        let old_content = fs::read_to_string(&old_file).unwrap();
        fs::remove_file(&new_file).ok();
        fs::remove_file(&old_file).ok();
        assert_eq!(new_mode, 0o600);
        assert_eq!(old_mode, 0o600);
        assert_eq!(old_content, "new");
    }

    #[test]
    fn test_append_to_ignores_uses_given_dir() {
        let dir = std::env::temp_dir().join(format!("dotenvx_ignores_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".dockerignore"), "target").unwrap();
        append_to_ignores(&dir, ".env.keys");
        assert_eq!(
            fs::read_to_string(dir.join(".gitignore")).unwrap(),
            ".env.keys\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join(".dockerignore")).unwrap(),
            "target\n.env.keys\n"
        );
        assert!(!dir.join(".aiignore").exists());
        // idempotent
        append_to_ignores(&dir, ".env.keys");
        assert_eq!(
            fs::read_to_string(dir.join(".gitignore")).unwrap(),
            ".env.keys\n"
        );
        // no .git: no .gitignore created
        let plain = dir.join("plain");
        fs::create_dir_all(&plain).unwrap();
        append_to_ignores(&plain, ".env.keys");
        assert!(!plain.join(".gitignore").exists());
        // a directory named .gitignore makes the write fail: warn, don't panic
        let broken = dir.join("broken");
        fs::create_dir_all(broken.join(".gitignore")).unwrap();
        append_to_ignores(&broken, ".env.keys");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_append_ignore_entry() {
        // last line without trailing newline: already present, not appended again
        assert_eq!(append_ignore_entry("target\n.env.keys", ".env.keys"), None);
        assert_eq!(append_ignore_entry("  .env.keys  \n", ".env.keys"), None);
        // `foo.env.keys` is not `.env.keys`
        assert_eq!(
            append_ignore_entry("foo.env.keys\n", ".env.keys").as_deref(),
            Some("foo.env.keys\n.env.keys\n")
        );
        // no trailing newline: entry goes on its own line
        assert_eq!(
            append_ignore_entry("target", ".env.keys").as_deref(),
            Some("target\n.env.keys\n")
        );
        assert_eq!(
            append_ignore_entry("", ".env.keys").as_deref(),
            Some(".env.keys\n")
        );
        // idempotent
        let once = append_ignore_entry("target", ".env.keys").unwrap();
        assert_eq!(append_ignore_entry(&once, ".env.keys"), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_restrict_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let file = dir.join(format!("dotenvx_perm_test_{}", uuid::Uuid::now_v7()));
        fs::write(&file, b"DOTENV_PRIVATE_KEY=secret").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        restrict_file_permissions(&file);
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        fs::remove_file(&file).ok();
        assert_eq!(mode, 0o600, "file should be owner-only after restriction");
    }

    #[test]
    #[ignore = "depends on the local .env.keys / DOTENV_PRIVATE_KEY of this machine"]
    fn test_get_private_key() {
        let private_key = get_private_key(&None).unwrap();
        assert!(EcKeyPair::from_secret_key(&private_key).is_ok());
    }

    #[test]
    fn test_get_public_key() {
        // .env.example is checked into the repository
        let public_key = get_public_key(&Some("example".to_owned())).unwrap();
        assert_eq!(
            public_key,
            "039dd52f537a84a560fd18600ff40856f3bfcc103e70f329acc21327622042b195"
        );
    }

    #[test]
    fn test_write_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env.test");
        let public_key = EcKeyPair::generate().get_pk_hex();
        write_public_key_to_file(&env_file, &public_key).unwrap();
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(content.contains(&format!("DOTENV_PUBLIC_KEY_TEST=\"{public_key}\"")));
        assert_eq!(
            get_public_key_for_file(env_file.to_str().unwrap()).unwrap(),
            public_key
        );
    }

    #[test]
    fn test_write_private_key_refuses_to_overwrite() {
        // write_private_key_to_file also writes the global key store, only run when isolated
        if test_support::isolated_dotenvx_dir().is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let keys_file = dir.path().join(KEYS_FILE_NAME);
        let old = EcKeyPair::generate();
        let old_content = format!("DOTENV_PRIVATE_KEY=\"{}\"\n", old.get_sk_hex());
        fs::write(&keys_file, &old_content).unwrap();
        assert!(private_key_exists_in_file(&keys_file, "DOTENV_PRIVATE_KEY"));
        assert!(!private_key_exists_in_file(
            &keys_file,
            "DOTENV_PRIVATE_KEY_PROD"
        ));
        let new = EcKeyPair::generate();
        let key_pair = KeyPair::new(&new.get_pk_hex(), &new.get_sk_hex(), &None);
        let result = write_private_key_to_file(&keys_file, "DOTENV_PRIVATE_KEY", &key_pair, false);
        assert!(result.is_err());
        // the existing private key is untouched, and nothing went to the global store
        assert_eq!(fs::read_to_string(&keys_file).unwrap(), old_content);
        assert!(
            DotenvxKeyStore::load_global()
                .map_or(true, |store| !store.keys.contains_key(&new.get_pk_hex()))
        );
    }

    #[test]
    fn test_write_private_key_overwrite_backs_up_old_key() {
        // write_private_key_to_file also writes the global key store, only run when isolated
        if test_support::isolated_dotenvx_dir().is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let keys_file = dir.path().join(KEYS_FILE_NAME);
        let old = EcKeyPair::generate();
        fs::write(
            &keys_file,
            format!("DOTENV_PRIVATE_KEY=\"{}\"\n", old.get_sk_hex()),
        )
        .unwrap();
        let new = EcKeyPair::generate();
        let key_pair = KeyPair::new(&new.get_pk_hex(), &new.get_sk_hex(), &None);
        write_private_key_to_file(&keys_file, "DOTENV_PRIVATE_KEY", &key_pair, true).unwrap();
        let content = fs::read_to_string(&keys_file).unwrap();
        assert!(content.contains(&format!("DOTENV_PRIVATE_KEY=\"{}\"", new.get_sk_hex())));
        // the old key pair is backed up, clean up both entries in the isolated store
        let (old_found, new_found) = DotenvxKeyStore::update_global(|store| {
            let old_found = store
                .keys
                .remove(&old.get_pk_hex())
                .map(|kp| kp.private_key);
            let new_found = store.keys.remove(&new.get_pk_hex()).is_some();
            Ok((true, (old_found, new_found)))
        })
        .unwrap();
        assert_eq!(old_found, Some(old.get_sk_hex()));
        assert!(new_found);
    }

    #[test]
    fn test_write_private_key() {
        // write_private_key_to_file also writes the global key store, only run when isolated
        let Some(dotenvx_dir) = test_support::isolated_dotenvx_dir() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        // an existing .env.keys: a new file would also update the ignore files in the cwd
        let keys_file = dir.path().join(KEYS_FILE_NAME);
        fs::write(&keys_file, "# keys\n").unwrap();
        let pair = EcKeyPair::generate();
        let key_pair = KeyPair::new(&pair.get_pk_hex(), &pair.get_sk_hex(), &None);
        write_private_key_to_file(&keys_file, "DOTENV_PRIVATE_KEY_TEST", &key_pair, false).unwrap();
        let content = fs::read_to_string(&keys_file).unwrap();
        assert!(content.contains(&format!(
            "DOTENV_PRIVATE_KEY_TEST=\"{}\"",
            pair.get_sk_hex()
        )));
        // the key pair went to the isolated global store, remove it again
        assert!(DotenvxKeyStore::global_path().starts_with(&dotenvx_dir));
        let removed = DotenvxKeyStore::update_global(|store| {
            let removed = store.keys.remove(&pair.get_pk_hex()).is_some();
            Ok((removed, removed))
        })
        .unwrap();
        assert!(removed, "key pair not written to the global key store");
    }

    #[test]
    #[ignore = "depends on a hard-coded file in the developer's home directory"]
    fn test_get_public_key_for_file() {
        let env_file = get_dotenvx_home().join(".env.g_default");
        let public_key = get_public_key_for_file(env_file.to_str().unwrap()).unwrap();
        assert!(!public_key.is_empty());
    }

    #[test]
    fn test_get_public_key_from_xml() {
        let public_key = get_public_key_from_text_file("tests/demo.xml").unwrap();
        assert_eq!(
            public_key,
            "02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0"
        );
    }

    #[test]
    fn test_get_public_key_from_json() {
        let public_key = get_public_key_from_text_file("tests/demo.json").unwrap();
        assert_eq!(
            public_key,
            "02e8d78f0da7fc3b529d503edd933ed8cdc79dbe5fd5d9bd480f1e63a09905f3b3"
        );
    }

    #[test]
    fn test_find_public_key_in_lines() {
        let key = "02e8d78f0da7fc3b529d503edd933ed8cdc79dbe5fd5d9bd480f1e63a09905f3b3";
        for content in [
            format!("DOTENV_PUBLIC_KEY=\"{key}\""),
            format!("dotenv.public.key: {key}"),
            format!("  \"dotenv.public.key\": \"{key}\","),
            format!("DOTENV_PUBLIC_KEY：'{key}'"),
        ] {
            assert_eq!(find_public_key_in_lines(&content).as_deref(), Some(key));
        }
        assert_eq!(find_public_key_in_lines("DOTENV_PUBLIC_KEY=abc"), None);
    }

    #[test]
    fn test_get_public_key_from_minified_json() {
        let key = "02e8d78f0da7fc3b529d503edd933ed8cdc79dbe5fd5d9bd480f1e63a09905f3b3";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.json");
        fs::write(
            &path,
            format!(r#"{{"name":"demo","dotenv.public.key":"{key}"}}"#),
        )
        .unwrap();
        let public_key = get_public_key_from_text_file(path.to_str().unwrap());
        assert_eq!(public_key.as_deref(), Some(key));
    }

    #[test]
    #[ignore = "depends on the global key store of this machine"]
    fn test_find_private_key_from_home() {
        let public_key = "028d59ff8bc98e7bfb7d7a0a6f511a653907cd3135db9ead01f293bcb7beb3ecd3";
        let private_key = find_private_key_from_home(public_key).unwrap();
        assert_eq!(
            EcKeyPair::from_secret_key(&private_key)
                .unwrap()
                .get_pk_hex(),
            public_key
        );
    }

    use crate::commands::crypt_util::{decrypt_env_item, encrypt_env_item};

    const TRICKY_VALUES: &[&str] = &[
        "$(touch /tmp/dotenvx_pwned)",
        "`id`",
        "$HOME",
        "${HOME}",
        r#"a"b"#,
        "it's",
        "'",
        "''",
        r"back\slash",
        r"trailing\",
        r"\n literal",
        "line1\nline2",
        "tab\tand space",
        "mixed '$x' \"`y`\" \\ end",
        "",
    ];

    fn parse_dotenv_line(line: &str) -> String {
        let entries: Vec<(String, String)> = dotenvy::from_read_iter(line.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("failed to parse {line:?}: {e}"));
        assert_eq!(entries.len(), 1, "line {line:?}");
        entries[0].1.clone()
    }

    /// `set` writes `K=<dotenv_double_quote>`; `get` / `encrypt` read the file back with dotenvy.
    #[test]
    fn test_dotenv_double_quote_round_trip() {
        for value in TRICKY_VALUES {
            let line = format!("K={}", dotenv_double_quote(value));
            assert_eq!(parse_dotenv_line(&line), *value, "set -> get for {line:?}");
        }
    }

    /// decrypt (write plaintext back) -> encrypt (re-read with dotenvy and encrypt) keeps the value.
    #[test]
    fn test_decrypt_encrypt_round_trip() {
        let pair = EcKeyPair::generate();
        let (pk, sk) = (pair.get_pk_hex(), pair.get_sk_hex());
        for value in TRICKY_VALUES {
            let encrypted = encrypt_env_item(&pk, value).unwrap();
            let decrypted = decrypt_env_item(&sk, &encrypted).unwrap();
            let line = format!("K={}", dotenv_double_quote(&decrypted));
            let plain = parse_dotenv_line(&line);
            let re_encrypted = encrypt_env_item(&pk, &plain).unwrap();
            assert_eq!(decrypt_env_item(&sk, &re_encrypted).unwrap(), *value);
        }
    }

    /// `--format shell` output must not execute anything under `eval` and must keep the value.
    #[cfg(unix)]
    #[test]
    fn test_shell_single_quote_eval() {
        for value in TRICKY_VALUES {
            let script = format!("export K={}", shell_single_quote(value));
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(r#"eval "$1" && printf '%s' "$K""#)
                .arg("sh")
                .arg(&script)
                .output()
                .unwrap();
            assert!(output.status.success(), "script {script:?} failed");
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                *value,
                "script {script:?}"
            );
        }
        assert!(!Path::new("/tmp/dotenvx_pwned").exists());
    }

    #[test]
    fn test_merge_env_keys_text() {
        let current = "# current\nDOTENV_PRIVATE_KEY_NEW=\"new\"\nDOTENV_PRIVATE_KEY=\"a2\"";
        let sealed = "# sealed\nDOTENV_PRIVATE_KEY=\"a1\"\n\nDOTENV_PRIVATE_KEY_OLD=\"old\"\n";
        let (merged, conflicts) = merge_env_keys_text(current, sealed);
        assert_eq!(
            merged,
            "# current\nDOTENV_PRIVATE_KEY_NEW=\"new\"\nDOTENV_PRIVATE_KEY=\"a2\"\nDOTENV_PRIVATE_KEY_OLD=\"old\"\n"
        );
        assert_eq!(conflicts, vec!["DOTENV_PRIVATE_KEY".to_owned()]);
        // nothing to merge into: the sealed keys are restored as-is
        let (merged, conflicts) = merge_env_keys_text("", sealed);
        assert_eq!(
            merged,
            "DOTENV_PRIVATE_KEY=\"a1\"\nDOTENV_PRIVATE_KEY_OLD=\"old\"\n"
        );
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_is_sensitive_key() {
        for key in [
            "DB_PASSWORD",
            "db_pwd",
            "SMTP_PASSWD",
            "GPG_PASSPHRASE",
            "JWT_ISSUER",
            "OAUTH_URL",
            "CLIENT_SECRET",
            "PRIVATE_URL",
            "KAFKA_JAAS",
            "API_KEY",
            "GITHUB_TOKEN",
            "AWS_CREDENTIALS",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
        for key in ["HOST", "PORT", "APP_NAME", "LOG_LEVEL", ""] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn test_key_patterns_case() {
        let keys = vec!["api*".to_string()];
        // .env: the pattern is upper-cased, but lower-case keys still match
        let patterns = compile_key_patterns(&keys, ".env").unwrap();
        assert!(patterns.matches("API_KEY"));
        assert!(patterns.matches("api_key"));
        assert!(!patterns.matches("DB_PASSWORD"));
        // .properties: keys are case-sensitive
        let patterns = compile_key_patterns(&keys, "application.properties").unwrap();
        assert!(patterns.matches("api.key"));
        assert!(!patterns.matches("API.KEY"));
    }

    #[test]
    fn test_adjust_env_key() {
        assert_eq!(adjust_env_key("api-token", ".env"), "API_TOKEN");
        assert_eq!(adjust_env_key("db.password", ".env.prod"), "DB_PASSWORD");
        assert_eq!(adjust_env_key("Mixed_Case", ".env"), "MIXED_CASE");
        // .properties keys are kept as they are
        assert_eq!(
            adjust_env_key("db.password", "application.properties"),
            "db.password"
        );
    }

    #[test]
    fn test_key_names_for_profile_and_file() {
        assert_eq!(get_public_key_name(&None), "DOTENV_PUBLIC_KEY");
        assert_eq!(
            get_public_key_name(&Some("prod".into())),
            "DOTENV_PUBLIC_KEY_PROD"
        );
        assert_eq!(get_private_key_name(&None), "DOTENV_PRIVATE_KEY");
        assert_eq!(
            get_private_key_name(&Some("g_default".into())),
            "DOTENV_PRIVATE_KEY_G_DEFAULT"
        );

        assert_eq!(get_public_key_name_for_file(".env"), "DOTENV_PUBLIC_KEY");
        assert_eq!(
            get_public_key_name_for_file("sub/.env.test"),
            "DOTENV_PUBLIC_KEY_TEST"
        );
        assert_eq!(
            get_public_key_name_for_file("application.properties"),
            "dotenv.public.key"
        );
        assert_eq!(
            get_public_key_name_for_file("src/main/resources/application-prod.properties"),
            "dotenv.public.key.prod"
        );
        assert_eq!(get_private_key_name_for_file(".env"), "DOTENV_PRIVATE_KEY");
        assert_eq!(
            get_private_key_name_for_file("configs/.env.stage"),
            "DOTENV_PRIVATE_KEY_STAGE"
        );
        assert_eq!(
            get_private_key_name_for_file("application-prod.properties"),
            "DOTENV_PRIVATE_KEY_PROD"
        );
    }

    #[test]
    fn test_public_key_name_detection() {
        assert!(is_public_key_name("DOTENV_PUBLIC_KEY"));
        assert!(is_public_key_name("DOTENV_PUBLIC_KEY_PROD"));
        assert!(is_public_key_name("dotenv.public.key.prod"));
        assert!(!is_public_key_name("DOTENV_PRIVATE_KEY"));
        assert!(is_public_key_included(
            "A=1\nDOTENV_PUBLIC_KEY_DEV=\"02ab\"\n"
        ));
        assert!(is_public_key_included("dotenv.public.key=02ab\n"));
        assert!(!is_public_key_included("A=1\nB=2\n"));
    }

    #[test]
    fn test_is_valid_env_key() {
        for key in ["A", "_A", "API_TOKEN", "a1_b2"] {
            assert!(is_valid_env_key(key), "{key}");
        }
        for key in ["", "1A", "A-B", "A.B", "A B", "A=B", "ÄPI"] {
            assert!(!is_valid_env_key(key), "{key}");
        }
    }

    #[test]
    fn test_is_remote_env_file() {
        assert!(is_remote_env_file("https://example.com/.env"));
        assert!(is_remote_env_file("http://localhost:8080/.env"));
        assert!(!is_remote_env_file(".env"));
        assert!(!is_remote_env_file("/etc/https/.env"));
    }

    #[test]
    fn test_construct_env_file_header() {
        let header = construct_env_file_header(
            "DOTENV_PUBLIC_KEY_PROD",
            "02abc",
            &Some("backend".into()),
            &Some("demo".into()),
        );
        assert!(header.starts_with("# ---\n# uuid: "), "{header}");
        assert!(
            header.contains("# name: demo\n# group: backend\n# ---\n"),
            "{header}"
        );
        assert!(
            header.contains("DOTENV_PUBLIC_KEY_PROD=\"02abc\""),
            "{header}"
        );
        // default name and group, the uuid is unique
        let default_header = construct_env_file_header("DOTENV_PUBLIC_KEY", "02abc", &None, &None);
        assert!(default_header.contains("# name: project_name\n# group: group_name\n"));
        assert_ne!(
            default_header,
            construct_env_file_header("DOTENV_PUBLIC_KEY", "02abc", &None, &None)
        );
        // the header is parsed as metadata, and the public key as an entry
        let entries: HashMap<String, String> = dotenvy::from_read_iter(default_header.as_bytes())
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            entries.get("DOTENV_PUBLIC_KEY").map(String::as_str),
            Some("02abc")
        );
    }

    #[test]
    fn test_list_env_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        for name in [
            ".env",
            ".env.prod",
            ".env.keys",
            ".env.vault",
            ".env.keys.json",
            ".env.keys.aes",
            ".env.keys.json.aes",
            ".env.keys.json.lock",
            ".env.keys.json.123.tmp",
            ".env.keys.tmp",
            ".env.prod.aes",
            ".env.prod.tmp",
            ".envrc",
            "app.env",
            "sub/.env.test",
            "sub/deeper/.env.dev",
        ] {
            fs::write(root.join(name), "A=1\n").unwrap();
        }
        let names = |max_depth: usize, profile: &Option<String>| {
            let mut names: Vec<String> = list_env_files(root, max_depth, profile)
                .iter()
                .map(|e| {
                    e.path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(1, &None), vec![".env", ".env.prod"]);
        assert_eq!(
            names(32, &None),
            vec![".env", ".env.prod", "sub/.env.test", "sub/deeper/.env.dev"]
        );
        assert_eq!(names(32, &Some("test".into())), vec!["sub/.env.test"]);
    }

    #[test]
    fn test_content_has_key_and_export_prefix() {
        let content = "# KEY=commented\nexport API_TOKEN=1\n  PORT = 8080\nAPI_TOKEN_2=2\n";
        assert!(content_has_key(content, "API_TOKEN"));
        assert!(content_has_key(content, "PORT"));
        assert!(!content_has_key(content, "KEY"));
        assert!(!content_has_key(content, "API"));

        assert!(line_has_export_prefix(".env", "export A=1"));
        assert!(!line_has_export_prefix(".env", "A=1"));
        assert!(line_has_export_prefix("env.sh", "# export A=1"));
        assert!(!line_has_export_prefix(
            "application.properties",
            "export A=1"
        ));
    }

    #[test]
    fn test_entry_line_count() {
        let lines = ["A=\"line1", "line2", "end\"", "B=1"];
        assert_eq!(entry_line_count(".env", &lines, 0), 3);
        assert_eq!(entry_line_count(".env", &lines, 3), 1);
        // escaped quote doesn't close a double-quoted value
        let lines = [r#"A="x\""#, "y\"", "B=2"];
        assert_eq!(entry_line_count(".env", &lines, 0), 2);
        // single-quoted values don't process escapes
        let lines = [r"A='x\'", "B=2"];
        assert_eq!(entry_line_count(".env", &lines, 0), 1);
        // unclosed quote: only the line itself
        let lines = ["A=\"never closed", "B=2"];
        assert_eq!(entry_line_count(".env", &lines, 0), 1);
        // .properties continuation lines
        let lines = [r"a=1 \", r"  2 \", "  3", "b=4"];
        assert_eq!(entry_line_count("app.properties", &lines, 0), 3);
        let lines = [r"a=1 \\", "b=4"];
        assert_eq!(entry_line_count("app.properties", &lines, 0), 1);
    }

    #[test]
    fn test_split_assignment() {
        assert_eq!(split_assignment(".env", "A=1"), Some(("", "A", "1")));
        assert_eq!(
            split_assignment(".env", "  export  API_TOKEN = \"x\""),
            Some(("  export  ", "API_TOKEN", "\"x\""))
        );
        assert_eq!(split_assignment(".env", "EMPTY="), Some(("", "EMPTY", "")));
        for line in ["", "   ", "# A=1", "  # A=1", "no separator", "=value"] {
            assert_eq!(split_assignment(".env", line), None, "{line:?}");
        }
        let props = "application.properties";
        assert_eq!(split_assignment(props, "a.b=1"), Some(("", "a.b", "1")));
        assert_eq!(split_assignment(props, "a.b: 1"), Some(("", "a.b", "1")));
        assert_eq!(split_assignment(props, "a.b 1"), Some(("", "a.b", "1")));
        assert_eq!(
            split_assignment(props, "  a.b = 1"),
            Some(("  ", "a.b", "1"))
        );
        // `export` is not a prefix in .properties files
        assert_eq!(
            split_assignment(props, "export=1"),
            Some(("", "export", "1"))
        );
        assert_eq!(split_assignment(props, "! comment"), None);
    }

    #[test]
    fn test_is_encrypted_value_text() {
        assert!(is_encrypted_value_text("encrypted:abc"));
        assert!(is_encrypted_value_text("\"encrypted:abc\""));
        assert!(is_encrypted_value_text("'encrypted:abc'"));
        assert!(!is_encrypted_value_text("\"has encrypted: inside\""));
        assert!(!is_encrypted_value_text("plain"));
    }
}
