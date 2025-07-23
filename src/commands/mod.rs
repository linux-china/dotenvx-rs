use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

pub mod decrypt;
pub mod encrypt;
pub mod run;

pub struct EcKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl EcKeyPair {
    pub fn generate() -> Self {
        let (sk, pk) = generate_keypair();
        EcKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn from_secret_key(sk_hex: &str) -> Self {
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk = SecretKey::parse_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);
        EcKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn get_pk_hex(self) -> String {
        let pk_compressed_bytes = self.public_key.serialize_compressed();
        hex::encode(pk_compressed_bytes)
    }

    pub fn get_sk_hex(self) -> String {
        let sk_bytes = self.secret_key.serialize();
        hex::encode(sk_bytes)
    }
}

pub fn read_dotenv_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    for item in dotenvy::from_filename_iter(path)? {
        if let Ok((key, value)) = item {
            entries.insert(key.clone(), value.clone());
        }
    }
    Ok(entries)
}

pub fn get_profile_name(env_file_name: &str) -> Option<String> {
    if env_file_name.starts_with(".env.") {
        let profile_name = env_file_name.replace(".env.", "");
        return Some(profile_name);
    }
    None
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
    let dotenv_file_path = PathBuf::from(".env.keys");
    if dotenv_file_path.exists() {
        let entries = read_dotenv_file(dotenv_file_path)?;
        if let Some(val) = entries.get(&env_key_name) {
            return Ok(val.trim_matches('"').to_owned());
        } else if let Some(val) = entries.get("DOTENV_PRIVATE_KEY") {
            return Ok(val.trim_matches('"').to_owned());
        }
    }
    // Fallback to checking the default environment variable directly
    if env_key_name != "DOTENV_PRIVATE_KEY" {
        if let Ok(private_key) = env::var("DOTENV_PRIVATE_KEY") {
            return Ok(private_key);
        }
    }
    Err("Private key not found".into())
}

pub fn get_public_key(profile_name: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = if let Some(name) = profile_name {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    };
    if let Ok(public_key) = env::var(&env_key_name) {
        return Ok(public_key);
    }
    let dotenv_file_path = if let Some(name) = profile_name {
        PathBuf::from(format!(".env.{}", name))
    } else {
        PathBuf::from(".env")
    };
    if dotenv_file_path.exists() {
        let entries = read_dotenv_file(dotenv_file_path)?;
        if let Some(val) = entries.get(&env_key_name) {
            return Ok(val.trim_matches('"').to_owned());
        } else if let Some(val) = entries.get("DOTENV_PUBLIC_KEY") {
            return Ok(val.trim_matches('"').to_owned());
        }
    }
    Err("Public key not found".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
