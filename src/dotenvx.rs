use crate::common::{get_profile_name_from_env, get_profile_name_from_file};
use base64::engine::general_purpose;
use base64::Engine;
use env::set_var;
use std::env;
use std::env::{home_dir, VarError};
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
    let private_key = get_private_key(&profile_name).ok();
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
    let private_key = get_private_key(&profile_name).ok();
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
    let private_key = get_private_key(&profile_name).ok();
    for x in dotenvy::from_filename_iter(filename)? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

pub fn from_read<R: Read>(reader: R) -> dotenvy::Result<()> {
    from_read_with_dotenvx(reader, false)
}

pub fn from_read_override<R: Read>(reader: R) -> dotenvy::Result<()> {
    from_read_with_dotenvx(reader, true)
}

pub fn from_read_iter<R: Read>(reader: R) -> dotenvy::Result<Vec<(String, String)>> {
    let mut items: Vec<(String, String)> = vec![];
    let private_key = get_private_key(&get_profile_name_from_env()).ok();
    for x in dotenvy::from_read_iter(reader) {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

fn from_path_with_dotenvx<P: AsRef<Path>>(env_file: P, is_override: bool) -> dotenvy::Result<()> {
    if env_file.as_ref().exists() {
        let dotenv_content = std::fs::read_to_string(&env_file).unwrap();
        if dotenv_content.contains("=encrypted:") {
            let env_file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
            let profile_name = get_profile_name_from_file(env_file_name);
            if let Ok(private_key) = get_private_key(&profile_name) {
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

fn from_read_with_dotenvx<R: Read>(reader: R, is_override: bool) -> dotenvy::Result<()> {
    let mut dotenv_content = String::new();
    reader
        .take(10 * 1024 * 1024) // Limit to 10MB to avoid excessive memory usage
        .read_to_string(&mut dotenv_content)
        .map_err(dotenvy::Error::Io)?;
    if dotenv_content.contains("=encrypted:") {
        let profile_name = get_profile_name_from_env();
        if let Ok(private_key) = get_private_key(&profile_name) {
            for item in dotenvy::from_read_iter(Cursor::new(dotenv_content.as_bytes())) {
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
        dotenvy::from_read_override(Cursor::new(dotenv_content.as_bytes()))?;
    } else {
        dotenvy::from_read(Cursor::new(dotenv_content.as_bytes()))?;
    }
    Ok(())
}

pub fn get_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = if let Some(name) = profile_name {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    };
    if let Ok(private_key) = env::var(&env_key_name) {
        return Ok(private_key);
    }
    let env_key_prefix = format!("{env_key_name}=");
    let mut dotenv_file_path = PathBuf::from(".env.keys");
    if !dotenv_file_path.exists() {
        dotenv_file_path = home_dir().unwrap().join(".env.keys");
    }
    if dotenv_file_path.exists() {
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
        general_purpose::STANDARD.decode(stripped_value).unwrap()
    } else {
        general_purpose::STANDARD.decode(encrypted_text).unwrap()
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
        let private_key = get_private_key(&None).unwrap();
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
