use crate::common::{
    find_dotenv_keys_file, find_env_file_path, get_profile_name_from_env,
    get_profile_name_from_file,
};
use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use chrono::{DateTime, Local};
use dirs::home_dir;
use env::set_var;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env::VarError;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::{env, fs};

/// load/decrypt .env file recursively from current directory to root directory
/// if profile name detected in environment, such as `NODE_ENV`, `RUN_ENV`, `APP_ENV` is set in env, it will load .env.{profile} file
pub fn dotenv() -> dotenvy::Result<()> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    let env_file_path = find_env_file_path(&env::current_dir().unwrap(), &env_file);
    if let Some(path) = env_file_path {
        return from_path_with_dotenvx(&path, true);
    }
    Ok(())
}

/// load/decrypt .env file recursively from current directory to root directory as a HashMap
pub fn dotenv_entries() -> dotenvy::Result<HashMap<String, String>> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    let mut entries = HashMap::new();
    let env_file_path = find_env_file_path(&env::current_dir().unwrap(), &env_file);
    if let Some(path) = env_file_path {
        if let Ok(items) = from_path_iter(path) {
            for (key, value) in items {
                entries.insert(key, value);
            }
        }
    }
    Ok(entries)
}

pub fn dotenv_override() -> dotenvy::Result<()> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    from_path_with_dotenvx(&env_file, true)
}

pub fn dotenv_iter<P: AsRef<Path>>() -> dotenvy::Result<Vec<(String, String)>> {
    let profile_name: Option<String> = None;
    let public_key = get_public_key(".env");
    let private_key = get_private_key(&public_key, &profile_name).ok();
    let mut items: Vec<(String, String)> = vec![];
    for x in dotenvy::dotenv_iter()? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

/// load/decrypt env_file from a given path
pub fn from_path<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<()> {
    from_path_with_dotenvx(&env_file, true)
}

pub fn from_path_override<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<()> {
    from_path_with_dotenvx(&env_file, true)
}

pub fn from_path_iter<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<Vec<(String, String)>> {
    let env_file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(env_file_name);
    let public_key = get_public_key(&env_file);
    let private_key = get_private_key(&public_key, &profile_name).ok();
    let mut items: Vec<(String, String)> = vec![];
    for x in dotenvy::from_path_iter(env_file)? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

pub fn from_filename<P: AsRef<Path>>(filename: P) -> dotenvy::Result<PathBuf> {
    let path = filename.as_ref().to_path_buf();
    if !path.exists() {
        return Err(dotenvy::Error::Io(std::io::Error::from(
            ErrorKind::NotFound,
        )));
    }
    from_path_with_dotenvx(&path, true)?;
    Ok(path)
}

pub fn from_filename_override<P: AsRef<Path>>(filename: P) -> dotenvy::Result<PathBuf> {
    let path = filename.as_ref().to_path_buf();
    if !path.exists() {
        return Err(dotenvy::Error::Io(std::io::Error::from(
            ErrorKind::NotFound,
        )));
    }
    from_path_with_dotenvx(&path, true)?;
    Ok(path)
}

pub fn from_filename_iter<P: AsRef<Path>>(filename: P) -> dotenvy::Result<Vec<(String, String)>> {
    let mut items: Vec<(String, String)> = vec![];
    let env_file_name = filename.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(env_file_name);
    let public_key = get_public_key(&filename);
    let private_key = get_private_key(&public_key, &profile_name).ok();
    for x in dotenvy::from_filename_iter(filename)? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

pub fn from_read<R: Read>(reader: R) -> dotenvy::Result<()> {
    from_read_with_dotenvx(reader)
}

pub fn from_read_iter<R: Read>(reader: R) -> dotenvy::Result<Vec<(String, String)>> {
    let mut items: Vec<(String, String)> = vec![];
    let entries = dotenvy::from_read_iter(reader)
        .map(|x| x.unwrap())
        .collect::<Vec<_>>();
    let public_key = get_public_key_from_entries(&entries);
    let private_key = get_private_key(&public_key, &get_profile_name_from_env()).ok();
    for (key, value) in entries {
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

fn from_path_with_dotenvx<P: AsRef<Path>>(env_file: P, is_override: bool) -> dotenvy::Result<()> {
    if env_file.as_ref().exists() {
        let dotenv_content = std::fs::read_to_string(&env_file).unwrap();
        if dotenv_content.contains("=encrypted:") {
            let public_key = get_public_key(&env_file);
            let env_file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
            let profile_name = get_profile_name_from_file(env_file_name);
            if let Ok(private_key) = get_private_key(&public_key, &profile_name) {
                for item in dotenvy::from_filename_iter(&env_file)? {
                    let (key, value) = item?;
                    let env_value = if value.starts_with("encrypted:") {
                        decrypt_dotenvx_item(&private_key, &value)?
                    } else {
                        value
                    };
                    set_env_var(&key, env_value, is_override);
                }
            } else {
                return Err(dotenvy::Error::EnvVar(VarError::NotPresent));
            }
        } else if is_override {
            dotenvy::from_filename_override(&env_file)?;
        } else {
            dotenvy::from_filename(env_file)?;
        }
    }
    Ok(())
}

fn get_public_key<P: AsRef<Path>>(env_file: P) -> Option<String> {
    if let Ok(mut result) = dotenvy::from_path_iter(env_file) {
        return result
            .find(|x| {
                x.as_ref()
                    .map(|(key, _)| key.starts_with("DOTENV_PUBLIC_KEY"))
                    .unwrap_or(false)
            })
            .map(|x| x.unwrap().1)
            .map(|key| key.trim_matches(|c| c == '"' || c == '\'').to_string());
    }
    None
}

fn get_public_key_from_entries(entries: &[(String, String)]) -> Option<String> {
    entries
        .iter()
        .find(|x| x.0 == "DOTENV_PUBLIC_KEY")
        .map(|x| {
            x.1.split("=")
                .nth(1)
                .unwrap_or("")
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
}

fn from_read_with_dotenvx<R: Read>(reader: R) -> dotenvy::Result<()> {
    let entries = dotenvy::from_read_iter(reader)
        .map(|x| x.unwrap())
        .collect::<Vec<_>>();
    let public_key = get_public_key_from_entries(&entries);
    let profile_name = get_profile_name_from_env();
    if let Ok(private_key) = get_private_key(&public_key, &profile_name) {
        for (key, value) in entries {
            let env_value = if value.starts_with("encrypted:") {
                decrypt_dotenvx_item(&private_key, &value)?
            } else {
                value
            };
            set_env_var(&key, env_value, true);
        }
    } else {
        return Err(dotenvy::Error::EnvVar(VarError::NotPresent));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DotenvxKeyStore {
    pub version: String,
    pub metadata: HashMap<String, String>,
    pub keys: HashMap<String, KeyPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPair {
    pub public_key: String,
    pub private_key: String,
    pub path: Option<String>,
    pub group: Option<String>,
    pub name: Option<String>,
    pub profile: Option<String>,
    pub comment: Option<String>,
    pub timestamp: Option<DateTime<Local>>,
}

impl DotenvxKeyStore {
    pub fn load_global() -> anyhow::Result<DotenvxKeyStore> {
        if let Some(env_keys_json_file) = Self::get_global_key_store_path() {
            let file_content = std::fs::read_to_string(env_keys_json_file)?;
            return if file_content.contains("\"version\"") {
                Ok(serde_json::from_str(&file_content)?)
            } else {
                let keys: HashMap<String, KeyPair> = serde_json::from_str(&file_content)?;
                let mut metadata = HashMap::new();
                metadata.insert("uuid".to_owned(), uuid::Uuid::now_v7().to_string());
                Ok(DotenvxKeyStore {
                    version: "0.1.0".to_string(),
                    metadata,
                    keys,
                })
            };
        }
        Err(anyhow!("Global key store(.env.keys.json) not found!"))
    }

    fn get_global_key_store_path() -> Option<PathBuf> {
        let dotenvx_home = home_dir().unwrap().join(".dotenvx");
        let env_keys_json_file = dotenvx_home.join(".env.keys.json");
        if env_keys_json_file.exists() {
            return Some(env_keys_json_file);
        } else if let Some(env_keys_json_file_from_usb) = Self::find_key_store_from_usb_disk() {
            return Some(env_keys_json_file_from_usb);
        }
        None
    }

    // The function is only included in the build when compiling for macOS
    #[cfg(target_os = "macos")]
    fn find_key_store_from_usb_disk() -> Option<PathBuf> {
        let key_store_path = PathBuf::from("/Volumes/Dotenvx/.dotenv.keys.json");
        if key_store_path.exists() {
            return Some(key_store_path);
        }
        None
    }

    #[cfg(target_os = "windows")]
    fn find_key_store_from_usb_disk() -> Option<PathBuf> {
        None
    }

    #[cfg(target_os = "linux")]
    fn find_key_store_from_usb_disk() -> Option<PathBuf> {
        let file = PathBuf::from("/proc/mounts");
        if !file.exists() {
            return None;
        }
        if let Ok(file_content) = fs::read_to_string(&file) {
            for line in file_content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let device = parts[0];
                    let mount_point = parts[1];
                    // Check for USB devices (common patterns)
                    if device.contains("/dev/sd") || device.contains("/dev/disk/by-id/usb") {
                        let file = PathBuf::from(&format!("{mount_point}/.dotenv/.env.keys.json"));
                        if file.exists() {
                            return Some(file);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn find_private_key(&self, public_key: &str) -> Option<String> {
        if let Some(key_pair) = self.keys.get(public_key) {
            return Some(key_pair.private_key.clone());
        }
        None
    }
}

pub fn get_private_key(
    public_key: &Option<String>,
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(public_key_hex) = public_key {
        if let Ok(global_store) = DotenvxKeyStore::load_global() {
            if let Some(private_key) = global_store.find_private_key(public_key_hex) {
                return Ok(private_key);
            }
        }
    }
    let env_key_name = if let Some(name) = profile_name {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    };
    if let Ok(private_key) = env::var(&env_key_name) {
        return Ok(private_key);
    }
    let env_key_prefix = format!("{env_key_name}=");
    let dotenv_keys_file = if let Some(profile) = profile_name
        && profile.starts_with("g_")
    {
        Some(home_dir().unwrap().join(".env.keys"))
    } else {
        find_dotenv_keys_file()
    };
    if let Some(dotenv_file_path) = dotenv_keys_file
        && dotenv_file_path.exists()
    {
        let dotenv_content = std::fs::read_to_string(dotenv_file_path)?;
        if let Some(dotenv_vault) = dotenv_content
            .lines()
            .find(|line| line.starts_with(&env_key_prefix))
        {
            return Ok(dotenv_vault[env_key_prefix.len()..]
                .trim_matches('"')
                .to_owned());
        }
    }
    Err("Private key not found".into())
}

// if the encrypted text starts with "encrypted:", it will decrypt it
fn check_and_decrypt(
    private_key: &Option<String>,
    encrypted_text: String,
) -> dotenvy::Result<String> {
    if let Some(tripped_value) = encrypted_text.strip_prefix("encrypted:") {
        if let Some(private_key) = private_key {
            decrypt_dotenvx_item(private_key, tripped_value)
        } else {
            Err(dotenvy::Error::EnvVar(VarError::NotPresent))
        }
    } else {
        Ok(encrypted_text)
    }
}

fn decrypt_dotenvx_item(private_key: &str, encrypted_text: &str) -> dotenvy::Result<String> {
    let encrypted_bytes = if let Some(stripped_value) = encrypted_text.strip_prefix("encrypted:") {
        Base64::decode_vec(stripped_value).unwrap()
    } else {
        Base64::decode_vec(encrypted_text).unwrap()
    };
    let sk = hex::decode(private_key).unwrap();
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes).unwrap();
    Ok(String::from_utf8(decrypted_bytes).unwrap())
}

fn set_env_var(key: &str, env_value: String, is_override: bool) {
    unsafe {
        if is_override || env::var(key).is_err() {
            set_var(key, env_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;

    #[test]
    fn test_load() {
        unsafe {
            set_var("HELLO", "Jackie");
        }
        dotenv_override().unwrap();
        assert_eq!(env::var("HELLO").unwrap(), "World");
    }

    #[test]
    fn test_load_global() {
        let store = DotenvxKeyStore::load_global().unwrap();
        println!("{:#?}", store);
    }

    #[test]
    fn test_ecies_decrypt() {
        let encrypted_text = "encrypted:BNexEwjKwt87k9aEgaSng1JY6uW8OkwMYEFTwEy/xyzDrQwQSDIUEXNlcwWi6rnvR1Q60G35NO4NWwhUYAaAON1LOnvMk+tJjTQJaM8DPeX2AJ8IzoTV44FLJsbOiMa77RLrnBv7";
        let private_key = get_private_key(&None, &None).unwrap();
        println!("private_key: {private_key}");
        let text = decrypt_dotenvx_item(&private_key, encrypted_text).unwrap();
        println!("{text}");
    }

    #[test]
    fn test_load_from_reader() {
        let dotenv_content = fs::read_to_string(".env").unwrap();
        let reader = Cursor::new(dotenv_content.as_bytes());
        from_read(reader).unwrap();
        assert_eq!(env::var("HELLO").unwrap(), "World");
        // Assuming the private key is set correctly in the environment,
        // The decryption will depend on the actual private key used
    }
    #[test]
    fn test_load_from_reader_iterator() {
        let dotenv_content = fs::read_to_string(".env").unwrap();
        let reader = Cursor::new(dotenv_content.as_bytes());
        for (key, value) in from_read_iter(reader).unwrap() {
            println!("{key}: {value}");
        }
        // Assuming the private key is set correctly in the environment
        // The decryption will depend on the actual private key used
    }

    #[test]
    fn test_find_private_key() {
        let public_key = "02336cf0909ec7473e6e45a46aedd998e955bfce282ade31a1fa8168a64b7f659d";
        get_private_key(&Some(public_key.to_string()), &None).expect("Failed to get a private key");
    }

    #[test]
    fn test_keystore() {
        DotenvxKeyStore::load_global().expect("Failed to load global keystore");
    }
}
