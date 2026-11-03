use base64ct::{Base64, Encoding};
use std::env;
use std::path::{Path, PathBuf};

/// Base64-decode an encrypted value, tolerating ASCII whitespace.
///
/// Long `encrypted:` values can be wrapped onto multiple lines by editors or tooling.
/// The standard base64 alphabet contains no whitespace, so stripping spaces, tabs,
/// and newlines before decoding is safe and only repairs accidental line wrapping.
pub fn decode_base64_lenient(value: &str) -> Result<Vec<u8>, base64ct::Error> {
    if value.bytes().any(|b| b.is_ascii_whitespace()) {
        let cleaned: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        Base64::decode_vec(&cleaned)
    } else {
        Base64::decode_vec(value)
    }
}

/// Directory of the global dotenvx store: `$DOTENVX_DIR` if set, otherwise `$HOME/.dotenvx`.
pub fn get_dotenvx_home() -> PathBuf {
    if let Ok(dotenvx_dir) = env::var("DOTENVX_DIR") {
        return PathBuf::from(dotenvx_dir);
    }
    dirs::home_dir().unwrap().join(".dotenvx")
}

pub fn get_profile_name_from_env() -> Option<String> {
    let env_vars = [
        "NODE_ENV",
        "RUN_ENV",
        "APP_ENV",
        "SPRING_PROFILES_ACTIVE",
        "MISE_ENV",
        "STELA_ENV",
        "SECRETSPEC_PROFILE",
    ];
    for var in env_vars.iter() {
        if let Ok(value) = env::var(var) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub fn get_profile_name_from_file(env_file: &str) -> Option<String> {
    let mut env_file_name = env_file;
    if env_file.contains("/") {
        env_file_name = env_file_name.rsplit('/').next().unwrap_or(env_file_name);
    } else if env_file.contains('\\') {
        env_file_name = env_file_name.rsplit('\\').next().unwrap_or(env_file_name);
    }
    if env_file_name.starts_with(".env.") {
        let profile_name = env_file_name.replace(".env.", "");
        return Some(profile_name);
    } else if env_file_name.ends_with(".properties") && env_file_name.contains('-') {
        return env_file_name
            .replace(".properties", "")
            .rsplit('-')
            .next()
            .map(|x| x.to_string());
    }
    None
}

pub fn find_dotenv_keys_file() -> Option<PathBuf> {
    let current_dir = env::current_dir().unwrap();
    find_dotenv_keys_file_by_path(&current_dir)
}

pub fn find_dotenv_keys_file_by_path(dir: &Path) -> Option<PathBuf> {
    if dir.join(".env.keys").exists() {
        return Some(dir.join(".env.keys"));
    } else if let Some(parent) = dir.parent() {
        return find_dotenv_keys_file_by_path(parent);
    }
    None
}

pub fn find_env_file_path(dir: &Path, env_file_name: &str) -> Option<PathBuf> {
    if dir.join(env_file_name).exists() {
        return Some(dir.join(env_file_name));
    } else if let Some(parent) = dir.parent() {
        return find_env_file_path(parent, env_file_name);
    }
    None
}

/// File name of the private keys file next to the env files.
pub const KEYS_FILE_NAME: &str = ".env.keys";

/// Name of the private key for the profile: `DOTENV_PRIVATE_KEY` or `DOTENV_PRIVATE_KEY_{PROFILE}`.
pub fn get_private_key_name(profile_name: &Option<String>) -> String {
    match profile_name {
        Some(name) => format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase()),
        None => "DOTENV_PRIVATE_KEY".to_string(),
    }
}

/// Strip the optional `{...}` suffix of a private key value.
pub fn trim_private_key(private_key_hex: String) -> String {
    match private_key_hex.find('{') {
        Some(pos) => private_key_hex[..pos].to_string(),
        None => private_key_hex,
    }
}

/// Compressed public key (hex) of the private key, `None` if the private key is invalid.
pub fn public_key_of_private_key(private_key_hex: &str) -> Option<String> {
    let sk_bytes = hex::decode(private_key_hex.trim()).ok()?;
    let sk = ecies::SecretKey::parse_slice(&sk_bytes).ok()?;
    Some(hex::encode(
        ecies::PublicKey::from_secret_key(&sk).serialize_compressed(),
    ))
}

fn is_global_profile(profile_name: &Option<String>) -> bool {
    profile_name.as_deref().is_some_and(|p| p.starts_with("g_"))
}

/// `.env.keys` for the profile without an env file: `$HOME/.env.keys` for global (`g_`) profiles,
/// otherwise the first one found from cwd upward.
pub fn get_dotenv_keys_file_path(profile_name: &Option<String>) -> Option<PathBuf> {
    if is_global_profile(profile_name) {
        dirs::home_dir().map(|home| home.join(KEYS_FILE_NAME))
    } else {
        find_dotenv_keys_file()
    }
}

/// `.env.keys` files to search for `env_file`: the one next to (or above) the file first,
/// then the one for the profile (cwd upward, or `$HOME/.env.keys` for `g_` profiles).
pub fn dotenv_keys_files_for_env_file(
    env_file: &Path,
    profile_name: &Option<String>,
) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(file_dir) = env_file.parent()
        && let Ok(file_dir) = std::fs::canonicalize(if file_dir.as_os_str().is_empty() {
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
            .any(|f| std::fs::canonicalize(&keys_file).is_ok_and(|k| &k == f))
    {
        files.push(keys_file);
    }
    files
}

/// Value of `key_name` in a `.env.keys` file. A missing or unreadable file yields `None`,
/// so the lookup goes on with the next source.
pub fn read_private_key_from_keys_file(keys_file: &Path, key_name: &str) -> Option<String> {
    dotenvy::from_path_iter(keys_file)
        .ok()?
        .map_while(Result::ok)
        .find(|(key, _)| key == key_name)
        .map(|(_, value)| value.trim().trim_matches('"').to_owned())
}

/// The global key store `$DOTENVX_DIR/.env.keys.json` (default `$HOME/.dotenvx/.env.keys.json`).
pub fn global_key_store_path() -> PathBuf {
    get_dotenvx_home().join(".env.keys.json")
}

/// Key store on a USB disk, used as a read-only fallback of the global key store.
#[cfg(target_os = "macos")]
fn find_key_store_from_usb_disk() -> Option<PathBuf> {
    let key_store_path = PathBuf::from("/Volumes/Dotenvx/.dotenv.keys.json");
    key_store_path.exists().then_some(key_store_path)
}

#[cfg(target_os = "linux")]
fn find_key_store_from_usb_disk() -> Option<PathBuf> {
    let file_content = std::fs::read_to_string("/proc/mounts").ok()?;
    for line in file_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [device, mount_point, ..] = parts.as_slice()
            && (device.contains("/dev/sd") || device.contains("/dev/disk/by-id/usb"))
        {
            let file = PathBuf::from(format!("{mount_point}/.dotenv/.env.keys.json"));
            if file.exists() {
                return Some(file);
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn find_key_store_from_usb_disk() -> Option<PathBuf> {
    None
}

/// Private key of `public_key` in key store json. The format is decided by the top-level `version`
/// field: `{"version", "metadata", "keys": {pk: KeyPair}}`, or the legacy `{pk: KeyPair}` map.
pub fn find_private_key_in_key_store_json(json_text: &str, public_key: &str) -> Option<String> {
    let json_value: serde_json::Value = serde_json::from_str(json_text).ok()?;
    let store = json_value.as_object()?;
    let keys = if store.contains_key("version") {
        store.get("keys")?.as_object()?
    } else {
        store
    };
    keys.get(public_key)?
        .get("private_key")?
        .as_str()
        .map(|private_key| trim_private_key(private_key.to_owned()))
}

/// Find the private key of `public_key` in the global key store, then in the key store on a USB disk.
pub fn find_private_key_in_global_store(public_key: &str) -> Option<String> {
    [
        Some(global_key_store_path()),
        find_key_store_from_usb_disk(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|path| std::fs::read_to_string(path).ok())
    .find_map(|json_text| find_private_key_in_key_store_json(&json_text, public_key))
}

/// Find the private key, shared by the CLI and the library (`run`, shims). Lookup order:
/// 1. `DOTENV_PRIVATE_KEY_{PROFILE}` environment variable
/// 2. `.env.keys`: the one next to (or above) `env_file` first, then the one from cwd upward
///    (`$HOME/.env.keys` for `g_` profiles)
/// 3. the global key store (`.env.keys.json`, then the USB disk)
/// 4. `DOTENV_PRIVATE_KEY` environment variable as the last resort for profiles
///
/// With `public_key`, every candidate is verified against it and a mismatched key is skipped.
/// Without `public_key`, only 1 and 2 are checked and the first candidate is returned.
pub fn find_private_key(
    public_key: Option<&str>,
    profile_name: &Option<String>,
    env_file: Option<&Path>,
) -> Result<String, String> {
    let env_key_name = get_private_key_name(profile_name);
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(private_key) = env::var(&env_key_name) {
        candidates.push(private_key);
    }
    let keys_files = match env_file {
        Some(env_file) => dotenv_keys_files_for_env_file(env_file, profile_name),
        None => get_dotenv_keys_file_path(profile_name)
            .into_iter()
            .collect(),
    };
    for keys_file in keys_files {
        if let Some(private_key) = read_private_key_from_keys_file(&keys_file, &env_key_name) {
            candidates.push(private_key);
        }
    }
    let Some(public_key) = public_key else {
        return candidates
            .into_iter()
            .next()
            .map(trim_private_key)
            .ok_or_else(|| format!("Private key not found: {env_key_name}"));
    };
    if let Some(private_key) = find_private_key_in_global_store(public_key) {
        candidates.push(private_key);
    }
    if env_key_name != "DOTENV_PRIVATE_KEY"
        && let Ok(private_key) = env::var("DOTENV_PRIVATE_KEY")
    {
        candidates.push(private_key);
    }
    candidates
        .into_iter()
        .map(trim_private_key)
        .find(|private_key| public_key_of_private_key(private_key).as_deref() == Some(public_key))
        .ok_or_else(|| {
            let target = env_file
                .map(|f| format!(" of {}", f.display()))
                .unwrap_or_default();
            format!(
                "Private key not found for public key {public_key}{target}: checked ${env_key_name}, .env.keys and the global key store"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_private_key_in_key_store_json() {
        let pk = "02aa";
        // new format, decided by the top-level `version`
        let new_format = r#"{"version":"0.1.0","metadata":{},"keys":{"02aa":{"public_key":"02aa","private_key":"sk1"}}}"#;
        assert_eq!(
            find_private_key_in_key_store_json(new_format, pk).as_deref(),
            Some("sk1")
        );
        // legacy format whose comment contains "version" is still the legacy format
        let legacy =
            r#"{"02aa":{"public_key":"02aa","private_key":"sk2{x}","comment":"\"version\""}}"#;
        assert_eq!(
            find_private_key_in_key_store_json(legacy, pk).as_deref(),
            Some("sk2")
        );
        assert_eq!(find_private_key_in_key_store_json(legacy, "02bb"), None);
        assert_eq!(find_private_key_in_key_store_json("not json", pk), None);
    }

    #[test]
    fn test_find_private_key_next_to_env_file() {
        let (sk, pk) = ecies::utils::generate_keypair();
        let sk_hex = hex::encode(sk.serialize());
        let pk_hex = hex::encode(pk.serialize_compressed());
        let dir = env::temp_dir().join(format!("dotenvx_common_lookup_{}", uuid::Uuid::now_v7()));
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        // a profile unique to this test, so no environment variable or cwd `.env.keys` can match
        let profile = Some(format!("t{}", uuid::Uuid::now_v7().simple()));
        let key_name = get_private_key_name(&profile);
        let env_file = sub.join(".env");
        std::fs::write(
            &env_file,
            format!(
                "DOTENV_PUBLIC_KEY={pk_hex}
"
            ),
        )
        .unwrap();
        // an unreadable `.env.keys` (a directory) is skipped instead of aborting the lookup
        std::fs::create_dir(sub.join(KEYS_FILE_NAME)).unwrap();
        assert!(find_private_key(Some(&pk_hex), &profile, Some(&env_file)).is_err());
        std::fs::remove_dir(sub.join(KEYS_FILE_NAME)).unwrap();
        std::fs::write(
            sub.join(KEYS_FILE_NAME),
            format!("{key_name}=\"{sk_hex}\"\n"),
        )
        .unwrap();
        assert_eq!(
            find_private_key(Some(&pk_hex), &profile, Some(&env_file)).unwrap(),
            sk_hex
        );
        // a mismatched public key is rejected
        let (_, other_pk) = ecies::utils::generate_keypair();
        let other_pk_hex = hex::encode(other_pk.serialize_compressed());
        let err = find_private_key(Some(&other_pk_hex), &profile, Some(&env_file)).unwrap_err();
        assert!(err.contains(&other_pk_hex), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_decode_base64_lenient() {
        let raw = b"the quick brown fox jumps over the lazy dog 0123456789";
        let encoded = Base64::encode_string(raw);
        // clean input decodes as usual
        assert_eq!(decode_base64_lenient(&encoded).unwrap(), raw);
        // editor-wrapped input with newlines, CR and spaces still decodes
        let mid = encoded.len() / 2;
        let wrapped = format!("{}\n  {}\r\n", &encoded[..mid], &encoded[mid..]);
        assert_eq!(decode_base64_lenient(&wrapped).unwrap(), raw);
    }
}
