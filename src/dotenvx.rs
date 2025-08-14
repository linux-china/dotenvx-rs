use crate::common::{find_dotenv_keys_file, get_profile_name_from_env, get_profile_name_from_file};
use base64ct::{Base64, Encoding};
use chrono::{DateTime, Local};
use dirs::home_dir;
use env::set_var;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::env::VarError;
use std::io::{Cursor, ErrorKind, Read};
use std::path::{Path, PathBuf};

pub fn dotenv() -> dotenvy::Result<()> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    from_path_with_dotenvx(&env_file, false)
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

pub fn from_path<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<()> {
    from_path_with_dotenvx(&env_file, false)
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
    from_path_with_dotenvx(&path, false)?;
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

fn find_all_keys() -> HashMap<String, KeyPair> {
    let dotenvx_home = dirs::home_dir().unwrap().join(".dotenvx");
    let env_keys_json_file = dotenvx_home.join(".env.keys.json");
    if env_keys_json_file.exists() {
        let file_content = std::fs::read_to_string(env_keys_json_file).unwrap();
        serde_json::from_str(&file_content).unwrap()
    } else {
        HashMap::new()
    }
}
pub fn get_private_key(
    public_key: &Option<String>,
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(public_key_hex) = public_key {
        let key_pairs = find_all_keys();
        if let Some(key_pair) = key_pairs.get(public_key_hex) {
            return Ok(key_pair.private_key.clone());
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

    #[test]
    fn test_load() {
        unsafe {
            set_var("HELLO", "Jackie");
        }
        dotenv_override().unwrap();
        assert_eq!(env::var("HELLO").unwrap(), "World");
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
        // Assuming the private key is set correctly in the environment
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
}
