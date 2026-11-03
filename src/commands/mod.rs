use crate::commands::crypt_util::EcKeyPair;
use crate::commands::framework::detect_framework;
use crate::commands::model::{DotenvxKeyStore, KeyPair};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use csv::WriterBuilder;
use dotenvx_rs::common::{
    find_dotenv_keys_file, find_dotenv_keys_file_by_path, find_env_file_path,
    get_profile_name_from_file,
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

const KEYS_FILE_NAME: &str = ".env.keys";

pub fn get_dotenvx_home() -> PathBuf {
    if let Ok(dotenvx_dir) = env::var("DOTENVX_DIR") {
        return PathBuf::from(dotenvx_dir);
    }
    dirs::home_dir().unwrap().join(".dotenvx")
}

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

pub fn find_private_key_from_home(public_key_hex: &str) -> Option<String> {
    if let Ok(key_store) = DotenvxKeyStore::load_global() {
        return key_store.find_private_key(public_key_hex);
    }
    None
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
/// Candidates: `DOTENV_PRIVATE_KEY_{PROFILE}` env var, `.env.keys` (next to the file and from cwd upward),
/// the global key store, and finally `DOTENV_PRIVATE_KEY`; each candidate is verified against the public key.
pub fn get_private_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    let public_key = get_public_key_for_file(env_file)?;
    if public_key.is_empty() {
        return get_private_key(&profile_name);
    }
    let env_key_name = get_private_key_name(&profile_name);
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(private_key) = env::var(&env_key_name) {
        candidates.push(private_key);
    }
    for keys_file in dotenv_keys_files_for_env_file(env_file, &profile_name) {
        if let Ok(entries) = read_dotenv_file(&keys_file)
            && let Some(private_key) = entries.get(&env_key_name)
        {
            candidates.push(private_key.trim_matches('"').to_owned());
        }
    }
    if let Some(private_key) = find_private_key_from_home(&public_key) {
        candidates.push(private_key);
    }
    if env_key_name != "DOTENV_PRIVATE_KEY"
        && let Ok(private_key) = env::var("DOTENV_PRIVATE_KEY")
    {
        candidates.push(private_key);
    }
    for private_key in candidates {
        let private_key = trim_private_key(private_key);
        if is_private_key_for(&private_key, &public_key) {
            return Ok(private_key);
        }
    }
    Err(format!(
        "Private key not found for public key {public_key} of {env_file}: checked ${env_key_name}, .env.keys and the global key store"
    )
    .into())
}

fn is_private_key_for(private_key: &str, public_key: &str) -> bool {
    EcKeyPair::from_input(private_key)
        .map(|kp| kp.get_pk_hex() == public_key)
        .unwrap_or(false)
}

/// `.env.keys` files to search for `env_file`: the one next to (or above) the file first, then the one from cwd.
fn dotenv_keys_files_for_env_file(env_file: &str, profile_name: &Option<String>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(file_dir) = Path::new(env_file).parent()
        && let Ok(file_dir) = fs::canonicalize(if file_dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            file_dir
        })
        && let Some(keys_file) = find_dotenv_keys_file_by_path(&file_dir)
    {
        files.push(keys_file);
    }
    if let Some(keys_file) = get_dotenv_keys_file_path(profile_name)
        && !files
            .iter()
            .any(|f| fs::canonicalize(&keys_file).is_ok_and(|k| &k == f))
    {
        files.push(keys_file);
    }
    files
}

/// read-only: find the private key from .env.keys or environment variables, never generate a new one
pub fn get_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_private_key_name(profile_name);
    lookup_private_key(profile_name)?
        .ok_or_else(|| format!("Private key not found: {env_key_name}").into())
}

fn get_dotenv_keys_file_path(profile_name: &Option<String>) -> Option<PathBuf> {
    if let Some(profile) = profile_name
        && profile.starts_with("g_")
    {
        dirs::home_dir().map(|home| home.join(KEYS_FILE_NAME))
    } else {
        find_dotenv_keys_file()
    }
}

fn lookup_private_key(
    profile_name: &Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let env_key_name = get_private_key_name(profile_name);
    let dotenv_keys_file_path = get_dotenv_keys_file_path(profile_name);
    let key_entries = if let Some(file_path) = &dotenv_keys_file_path {
        read_dotenv_file(file_path)?
    } else {
        HashMap::new()
    };
    // read from .env.keys file
    if let Some(private_key) = key_entries.get(&env_key_name) {
        return Ok(Some(trim_private_key(
            private_key.trim_matches('"').to_owned(),
        )));
    }
    // read from environment variables
    if let Ok(private_key) = env::var(&env_key_name) {
        return Ok(Some(trim_private_key(private_key)));
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
    if let Some(file_path) = &dotenv_keys_file_path {
        write_private_key_to_file(file_path, &env_key_name, &key_pair)?;
    } else {
        // if .env.keys file not found, create it in the current directory
        let file_path = PathBuf::from(KEYS_FILE_NAME);
        write_private_key_to_file(&file_path, &env_key_name, &key_pair)?;
    }
    // make sure the new private key is persisted, otherwise values encrypted with it can never be decrypted
    match lookup_private_key(profile_name)? {
        Some(saved_key) if saved_key == private_key_hex => Ok(saved_key),
        _ => {
            Err(format!("Failed to save new private key {env_key_name} to {KEYS_FILE_NAME}").into())
        }
    }
}

fn trim_private_key(private_key_hex: String) -> String {
    if private_key_hex.contains("{") {
        private_key_hex[0..private_key_hex.find('{').unwrap()].to_string()
    } else {
        private_key_hex
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

fn resolve_public_key(
    profile_name: &Option<String>,
    create: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_public_key_name(profile_name);
    let env_file_name = if let Some(name) = profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_string()
    };
    let dotenv_file_path = if let Some(profile) = profile_name
        && profile.starts_with("g_")
    {
        dirs::home_dir()
            .unwrap()
            .join(".dotenvx")
            .join(env_file_name)
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
        return Ok(val.trim_matches('"').to_owned());
    }
    // read from environment variables
    if let Ok(public_key) = env::var(&env_key_name) {
        return Ok(public_key);
    }
    // get public key from the default private key
    let private_key_hex = if create {
        get_or_create_private_key(profile_name)?
    } else {
        get_private_key(profile_name)?
    };
    let kp = EcKeyPair::from_secret_key(&private_key_hex);
    Ok(kp.get_pk_hex())
}

pub fn get_public_key_from_text_file(file_path: &str) -> Option<String> {
    if Path::new(file_path).exists() {
        if let Ok(content) = fs::read_to_string(file_path) {
            // extract the public key by text parsing
            for line in content.lines() {
                let line = line.trim();
                if line.contains("dotenv.public.key") || line.contains("DOTENV_PUBLIC_KEY") {
                    let result = line
                        .split(['=', ':', '：'])
                        .nth(1)
                        .map(|s| s.trim().to_string())
                        .map(|s| {
                            s.split([',', ';', '}', ']', ')', ' ', '-', '_'])
                                .next()
                                .unwrap()
                                .trim()
                                .to_string()
                        })
                        .map(|s| s.trim_matches(['"', '\'']).to_string())
                        .filter(|s| s.len() == 66);
                    if result.is_some() {
                        return result;
                    }
                }
            }
            if file_path.ends_with(".json") {
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Ok(pretty_json_text) = serde_json::to_string_pretty(&json_value) {
                        for line in pretty_json_text.lines() {
                            let line = line.trim();
                            if line.contains("dotenv.public.key")
                                || line.contains("DOTENV_PUBLIC_KEY")
                            {
                                let result = line
                                    .split([':'])
                                    .nth(1)
                                    .map(|s| s.trim().to_string())
                                    .map(|s| {
                                        s.split([',', ';', '}', ']', ')', ' ', '-', '_'])
                                            .next()
                                            .unwrap()
                                            .trim()
                                            .to_string()
                                    })
                                    .map(|s| s.trim_matches(['"', '\'']).to_string())
                                    .filter(|s| s.len() == 66);
                                if result.is_some() {
                                    return result;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
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
            fs::write(&env_file, file_content.as_bytes()).unwrap();
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
            fs::write(&env_file, file_content.trim_start().as_bytes()).unwrap();
        } else {
            fs::write(
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
        fs::write(&env_file, new_content).unwrap();
    } else if content.ends_with("\n") {
        fs::write(&env_file, content).unwrap();
    } else {
        fs::write(&env_file, format!("{content}\n")).unwrap();
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

/// 读取 `key` 对应的值（去掉两侧引号），不存在返回 None
fn get_key_value_in_content(content: &str, key: &str) -> Option<String> {
    content.lines().find(|line| line_has_key(line, key)).map(|line| {
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
        fs::write(&env_file, header_text.trim_start().as_bytes())?;
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
            fs::write(&env_file, file_content.as_bytes())?;
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
            fs::write(&env_file, new_content.as_bytes())?;
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

pub fn write_private_key_to_file<P: AsRef<Path>>(
    env_keys_file: P,
    private_key_name: &str,
    key_pair: &KeyPair,
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
        fs::write(&env_keys_file, file_content.trim_start().as_bytes())?;

        println!(
            "{}",
            format!("✔ {file_name} file created with the private key({private_key_short}...)")
                .green()
        );
        append_to_ignores(KEYS_FILE_NAME);
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
            fs::write(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) added in {file_name}").green()
            );
        } else if existing_private_key.as_deref() != Some(private_key_value.as_str()) {
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
            fs::write(&env_keys_file, new_content.as_bytes())?;
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
    let env_file_arg = command_matches.get_one::<String>("env-file");
    // specified .env file argument takes precedence
    if let Some(env_file) = env_file_arg {
        return env_file.clone();
    }
    // load env file by profile
    let dotenv_file = if let Some(profile_name) = profile {
        if profile_name.starts_with("g_") {
            let dotenvx_home = dirs::home_dir().unwrap().join(".dotenvx");
            format!("{}/.env.{profile_name}", dotenvx_home.display())
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

pub fn get_private_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
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

pub fn append_to_ignores(file_name: &str) {
    // git repository but no .gitignore file
    if Path::new(".git").exists() && !Path::new(".gitignore").exists() {
        fs::write(".gitignore", format!("{file_name}\n")).unwrap();
    }
    let ignore_files = [".gitignore", ".dockerignore", ".aiignore"];
    for ignore_file in &ignore_files {
        let path = PathBuf::from(ignore_file);
        if path.exists() {
            let mut content = fs::read_to_string(&path).unwrap_or_default();
            if !content.contains(format!("{file_name}\n").as_str()) {
                content.push_str(&format!("\n{file_name}"));
                fs::write(&path, content).expect("Failed to write to ignore file");
                println!(
                    "{}",
                    format!("✔ {file_name} added to {ignore_file}").green()
                );
            } else {
                println!(
                    "{}",
                    format!("✔ {file_name} already exists in {ignore_file}").green()
                );
            }
        }
    }
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
        .filter(|e| {
            let file_name = e.file_name().to_str().unwrap();
            if file_name == ".env.keys" || file_name == ".env.vault" {
                false
            } else {
                file_name.starts_with(".env.") || file_name == ".env"
            }
        })
        .filter(|e| {
            // filter by profile if provided
            let file_name = e.file_name().to_str().unwrap();
            if let Some(profile_name) = profile {
                let env_file_name = format!(".env.{profile_name}");
                file_name.starts_with(&env_file_name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_and_private_key_from_file_in_sub_dir() {
        let dir = std::env::temp_dir().join(format!("dotenvx_file_key_test_{}", uuid::Uuid::now_v7()));
        let sub_dir = dir.join("sub").join("dir");
        fs::create_dir_all(&sub_dir).unwrap();
        let kp = EcKeyPair::generate();
        let other = EcKeyPair::generate();
        let env_file = sub_dir.join(".env.prod");
        fs::write(&env_file, format!("DOTENV_PUBLIC_KEY_PROD=\"{}\"\nA=1\n", kp.get_pk_hex())).unwrap();
        // the key for the profile lives in the .env.keys next to the file, a stale default key is ignored
        fs::write(
            sub_dir.join(KEYS_FILE_NAME),
            format!("DOTENV_PRIVATE_KEY={}\nDOTENV_PRIVATE_KEY_PROD={}\n", other.get_sk_hex(), kp.get_sk_hex()),
        )
        .unwrap();
        let env_file = env_file.to_str().unwrap();
        assert_eq!(get_public_key_for_file(env_file).unwrap(), kp.get_pk_hex());
        assert_eq!(get_private_key_for_file(env_file).unwrap(), kp.get_sk_hex());
        // a file name without profile: its own declared key is used
        let app_env = sub_dir.join("app.env");
        fs::write(&app_env, format!("DOTENV_PUBLIC_KEY_PROD={}\n", kp.get_pk_hex())).unwrap();
        assert_eq!(get_public_key_for_file(app_env.to_str().unwrap()).unwrap(), kp.get_pk_hex());
        // properties file
        let props = sub_dir.join("application-prod.properties");
        fs::write(&props, format!("dotenv.public.key.prod={}\na=1\n", kp.get_pk_hex())).unwrap();
        assert_eq!(get_public_key_for_file(props.to_str().unwrap()).unwrap(), kp.get_pk_hex());
        // a private key that doesn't match the public key is rejected
        fs::write(sub_dir.join(KEYS_FILE_NAME), format!("DOTENV_PRIVATE_KEY_PROD={}\n", other.get_sk_hex())).unwrap();
        assert!(get_private_key_for_file(env_file).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_public_key_for_missing_properties_file_no_panic() {
        let file = std::env::temp_dir().join(format!("dotenvx_missing_{}", uuid::Uuid::now_v7())).join("application.properties");
        let _ = get_public_key_for_file(file.to_str().unwrap());
    }

    #[test]
    fn test_line_has_key_exact_match() {
        assert!(line_has_key("DOTENV_PUBLIC_KEY=\"abc\"", "DOTENV_PUBLIC_KEY"));
        assert!(line_has_key("  export KEY = 1", "KEY"));
        assert!(!line_has_key("DOTENV_PUBLIC_KEY_PROD=\"abc\"", "DOTENV_PUBLIC_KEY"));
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
        if std::env::var("DOTENVX_DIR").is_err() {
            eprintln!("skip: DOTENVX_DIR not set");
            return;
        }
        let dir = std::env::temp_dir().join(format!("dotenvx_sk_test_{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let keys_file = dir.join(".env.keys");
        fs::write(&keys_file, "DOTENV_PRIVATE_KEY_PROD=\"prod_sk\"\n").unwrap();
        let mut key_pair = KeyPair::new("default_pub_test", "default_sk_test", &None);
        key_pair.path = Some(dir.to_string_lossy().to_string());
        write_private_key_to_file(&keys_file, "DOTENV_PRIVATE_KEY", &key_pair).unwrap();
        let content = fs::read_to_string(&keys_file).unwrap();
        assert!(content.contains("DOTENV_PRIVATE_KEY_PROD=\"prod_sk\""));
        assert!(content.contains("DOTENV_PRIVATE_KEY=\"default_sk_test\""));
        fs::remove_dir_all(&dir).unwrap();
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
    fn test_get_private_key() {
        let profile_name = None;
        let private_key = get_private_key(&profile_name);
        println!("private key: {}", private_key.unwrap());
    }

    #[test]
    fn test_get_public_key() {
        let profile_name = Some("example".to_owned());
        let public_key = get_public_key(&profile_name);
        println!("public key: {}", public_key.unwrap());
    }

    #[test]
    fn test_write_public_key() {
        let public_key = "xxxx";
        let env_file = PathBuf::from(".env.test");
        write_public_key_to_file(&env_file, public_key).unwrap();
    }

    #[test]
    fn test_write_private_key() {
        let env_file = PathBuf::from(KEYS_FILE_NAME);
        let key_pair = KeyPair::new("xxxx", "yyyyy", &None);
        write_private_key_to_file(&env_file, "DOTENV_PRIVATE_KEY_TEST", &key_pair).unwrap();
    }

    #[test]
    fn test_get_public_key_for_file() {
        let env_file = "/Users/linux_china/.dotenvx/.env.g_default";
        let public_key = get_public_key_for_file(env_file);
        println!("public key: {}", public_key.unwrap());
    }

    #[test]
    fn test_get_public_key_from_xml() {
        let file_path = "tests/demo.xml";
        let public_key = get_public_key_from_text_file(file_path).unwrap();
        println!("public key: {public_key}");
    }

    #[test]
    fn test_get_public_key_from_json() {
        let file_path = "tests/demo.json";
        let public_key = get_public_key_from_text_file(file_path).unwrap();
        println!("public key: {public_key}");
    }

    #[test]
    fn tes_find_private_key() {
        let private_key = find_private_key_from_home(
            "028d59ff8bc98e7bfb7d7a0a6f511a653907cd3135db9ead01f293bcb7beb3ecd3",
        );
        println!("private key: {private_key:?}")
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
            assert_eq!(String::from_utf8(output.stdout).unwrap(), *value, "script {script:?}");
        }
        assert!(!Path::new("/tmp/dotenvx_pwned").exists());
    }
}
