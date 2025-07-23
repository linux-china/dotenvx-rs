use crate::common::{get_profile_name_from_env, get_profile_name_from_file};
use base64::engine::general_purpose;
use base64::Engine;
use std::env;
use std::env::home_dir;
use std::path::{Path, PathBuf};

pub fn dotenv() -> Result<(), Box<dyn std::error::Error>> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{}", name)
    } else {
        ".env".to_owned()
    };
    from_path(&env_file)
}

pub fn from_path<P: AsRef<Path>>(env_file: P) -> Result<(), Box<dyn std::error::Error>> {
    if env_file.as_ref().exists() {
        let dotenv_content = std::fs::read_to_string(&env_file)?;
        if dotenv_content.contains("=encrypted:") {
            let profile_name = get_profile_name_from_file(
                env_file.as_ref().file_name().unwrap().to_str().unwrap(),
            );
            let private_key = get_private_key(&profile_name)?;
            for item in dotenvy::from_filename_iter(&env_file)? {
                let (key, value) = item?;
                let env_value = if value.starts_with("encrypted:") {
                    decrypt_env_item(&private_key, &value)?
                } else {
                    value
                };
                unsafe {
                    env::set_var(&key, env_value);
                }
            }
        } else {
            dotenvy::from_filename_override(&env_file)?;
        }
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
    let env_key_prefix = format!("{}=", env_key_name);
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

fn decrypt_env_item(
    private_key: &str,
    encrypted_text: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = if encrypted_text.starts_with("encrypted:") {
        general_purpose::STANDARD
            .decode(&encrypted_text[10..])
            .unwrap()
    } else {
        general_purpose::STANDARD.decode(encrypted_text).unwrap()
    };
    let sk = hex::decode(private_key).unwrap();
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes).unwrap();
    Ok(String::from_utf8(decrypted_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecies_decrypt() {
        let encrypted_text = "encrypted:BNexEwjKwt87k9aEgaSng1JY6uW8OkwMYEFTwEy/xyzDrQwQSDIUEXNlcwWi6rnvR1Q60G35NO4NWwhUYAaAON1LOnvMk+tJjTQJaM8DPeX2AJ8IzoTV44FLJsbOiMa77RLrnBv7";
        let private_key = get_private_key(&None).unwrap();
        println!("private_key: {}", private_key);
        let text = decrypt_env_item(&private_key, encrypted_text).unwrap();
        println!("{}", text);
    }
}
