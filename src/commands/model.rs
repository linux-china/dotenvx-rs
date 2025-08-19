use crate::commands::crypt_util::{
    decrypt_env_item, encrypt_env_item, sign_message, verify_signature,
};
use crate::commands::{get_dotenvx_home, is_public_key_name};
use anyhow::anyhow;
use chrono::{DateTime, Local};
use dotenvx_rs::common::get_profile_name_from_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotenvxKeyStore {
    pub version: String,
    pub metadata: HashMap<String, String>,
    pub keys: HashMap<String, KeyPair>,
}

impl DotenvxKeyStore {
    pub fn new() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("uuid".to_owned(), uuid::Uuid::now_v7().to_string());
        DotenvxKeyStore {
            version: "0.1.0".to_string(),
            metadata,
            keys: HashMap::new(),
        }
    }
    pub fn load_global() -> anyhow::Result<DotenvxKeyStore> {
        let dotenvx_home = get_dotenvx_home();
        let env_keys_json_file = dotenvx_home.join(".env.keys.json");
        if env_keys_json_file.exists() {
            let file_content = fs::read_to_string(env_keys_json_file)?;
            return if file_content.contains("\"version\"") {
                Ok(serde_json::from_str(&file_content)?)
            } else {
                let keys: HashMap<String, KeyPair> = serde_json::from_str(&file_content)?;
                Ok(DotenvxKeyStore {
                    version: "0.0.0".to_string(),
                    metadata: HashMap::new(),
                    keys,
                })
            };
        }
        Err(anyhow!("$HOME/.dotenvx/.env.keys.json not foud"))
    }

    pub fn find_private_key(&self, public_key: &str) -> Option<String> {
        if let Some(key_pair) = self.keys.get(public_key) {
            return Some(key_pair.private_key.clone());
        }
        None
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let dotenvx_home = get_dotenvx_home();
        if !dotenvx_home.exists() {
            fs::create_dir_all(&dotenvx_home)?;
        }
        let env_keys_json_file = dotenvx_home.join(".env.keys.json");
        let file_content = serde_json::to_string_pretty(self)?;
        fs::write(env_keys_json_file, file_content)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
    pub path: Option<String>,
    pub group: Option<String>,
    pub name: Option<String>,
    pub profile: Option<String>,
    pub comment: Option<String>,
    pub timestamp: Option<DateTime<Local>>,
}

impl KeyPair {
    pub fn new(public_key: &str, private_key: &str, profile: &Option<String>) -> Self {
        KeyPair {
            public_key: public_key.to_string(),
            private_key: private_key.to_string(),
            path: None,
            group: None,
            name: None,
            profile: profile.clone(),
            comment: None,
            timestamp: Some(Local::now()),
        }
    }
    pub fn from(
        public_key: &str,
        private_key: &str,
        group: &Option<String>,
        name: &Option<String>,
        profile: &Option<String>,
    ) -> Self {
        KeyPair {
            public_key: public_key.to_string(),
            private_key: private_key.to_string(),
            path: None,
            group: group.clone(),
            name: name.clone(),
            profile: profile.clone(),
            comment: None,
            timestamp: Some(Local::now()),
        }
    }
}

pub struct EnvKeys {
    pub metadata: Option<HashMap<String, String>>,
    pub keys: Option<Vec<String>>,
    pub source: Option<String>,
}

impl EnvKeys {
    pub fn from_file<P: AsRef<Path>>(env_keys_file_path: P) -> anyhow::Result<EnvKeys> {
        let content = fs::read_to_string(&env_keys_file_path)?;
        let metadata = extract_front_matter(&content);
        let keys: Vec<String> = content
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();
        Ok(EnvKeys {
            metadata: Some(metadata),
            keys: Some(keys),
            source: Some(env_keys_file_path.as_ref().to_string_lossy().to_string()),
        })
    }

    pub fn new<P: AsRef<Path>>(env_keys_file_path: P) -> Self {
        let keys_uuid = uuid::Uuid::now_v7().to_string();
        let mut metadata = HashMap::new();
        metadata.insert("uuid".to_string(), keys_uuid);
        EnvKeys {
            metadata: Some(metadata),
            keys: Some(Vec::new()),
            source: Some(env_keys_file_path.as_ref().to_string_lossy().to_string()),
        }
    }

    pub fn write(&self) -> anyhow::Result<()> {
        let mut content = String::new();
        if let Some(metadata) = &self.metadata {
            content.push_str("# ---\n");
            if !metadata.contains_key("uuid") {
                let keys_uuid = uuid::Uuid::now_v7().to_string();
                content.push_str(&format!("# uuid: {keys_uuid}\n"));
            }
            for (key, value) in metadata {
                content.push_str(&format!("# {key}: {value}\n"));
            }
            content.push_str("# ---\n\n");
        }
        if let Some(keys) = &self.keys {
            for key in keys {
                content.push_str(&format!("{key}\n"));
            }
        }
        let file_path = self
            .source
            .as_ref()
            .ok_or_else(|| anyhow!("Source path is not set"))?;
        fs::write(file_path, content)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EnvFile {
    pub name: String,
    pub source: Option<String>,
    pub content: String,
    pub profile: Option<String>,
    pub metadata: HashMap<String, String>,
    pub entries: HashMap<String, String>,
}

impl EnvFile {
    pub fn from<P: AsRef<Path>>(env_file_path: P) -> Result<Self, std::io::Error> {
        let file_name = env_file_path
            .as_ref()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let mut path: Option<String> = None;
        if let Ok(path_buf) = &env_file_path.as_ref().canonicalize() {
            path = Some(path_buf.to_str().unwrap().to_string());
        }
        let file = File::open(&env_file_path)?;
        Self::from_read(file_name, path, file)
    }

    pub fn from_read<R: Read>(
        name: &str,
        source: Option<String>,
        mut reader: R,
    ) -> Result<Self, std::io::Error> {
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        let profile = if name.starts_with(".env.") {
            Some(name.replace(".env.", ""))
        } else {
            None
        };
        let metadata = extract_front_matter(&content);
        if let Ok(entries) = read_dotenv_entries(&content) {
            Ok(EnvFile {
                name: name.to_string(),
                source,
                content,
                profile,
                metadata,
                entries,
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to read dotenv entries",
            ))
        }
    }
}

impl EnvFile {
    pub fn is_signed(&self) -> bool {
        self.content.contains("# sign:") || self.content.contains("#sign:")
    }

    pub fn get_uuid(&self) -> Option<&String> {
        self.metadata.get("uuid")
    }

    pub fn get_public_key(&self) -> Option<String> {
        for (key, value) in &self.entries {
            if is_public_key_name(key) {
                return Some(value.clone());
            }
        }
        None
    }

    pub fn is_verified(&self) -> bool {
        if let Some(signature) = get_signature(&self.content) {
            let message = remove_signature(&self.content);
            let public_key = self.get_public_key();
            if let Some(public_key) = public_key {
                verify_signature(&public_key, &message, &signature).unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        }
    }
}

struct ApplicationProperties {
    pub profile: Option<String>,
    pub metadata: HashMap<String, String>,
    pub entries: HashMap<String, String>,
    pub content: String,
    pub source: Option<String>,
}

impl ApplicationProperties {
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(&file_path)?;
        let metadata = extract_front_matter(&content);
        let entries = dotenvy::from_read_iter(Cursor::new(content.as_bytes()))
            .flatten()
            .collect();
        let file_name = file_path
            .as_ref()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("application.properties")
            .to_string();
        let profile = get_profile_name_from_file(&file_name);
        Ok(ApplicationProperties {
            profile,
            metadata,
            entries,
            content,
            source: Some(file_path.as_ref().to_string_lossy().to_string()),
        })
    }
}

pub fn read_dotenv_entries(
    content: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    let reader = Cursor::new(content.as_bytes());
    for (key, value) in dotenvy::from_read_iter(reader).flatten() {
        entries.insert(key.clone(), value.clone());
    }
    Ok(entries)
}

fn extract_front_matter(content: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    if content.starts_with("# ---") || content.starts_with("#---") {
        let mut lines = content.lines();
        // Skip the first line
        lines.next();
        // Read until we find the end marker
        for line in lines {
            if line.starts_with("# ---") || line.starts_with("#---") {
                break;
            }
            if let Some((key, value)) = line.trim_start_matches("#").trim().split_once(':') {
                metadata.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    metadata
}

pub fn sign_available(env_file_content: &str) -> bool {
    env_file_content
        .lines()
        .any(|line| line.starts_with("# sign:") || line.starts_with("#sign:"))
}

pub fn get_signature(env_file_content: &str) -> Option<String> {
    // Find the signature line
    for line in env_file_content.lines() {
        if line.starts_with("# sign:") || line.starts_with("#sign:") {
            return Some(line.trim_start_matches("# sign:").trim().to_string());
        }
    }
    None
}

pub fn is_sign_legal(env_file_content: &str, public_key: &str) -> anyhow::Result<bool> {
    if let Some(signature) = get_signature(env_file_content) {
        let message = remove_signature(env_file_content);
        verify_signature(public_key, &message, &signature)
    } else {
        Err(anyhow::anyhow!(
            "The .env file does not contain a valid signature."
        ))
    }
}

pub fn remove_signature(env_file_content: &str) -> String {
    // Remove lines starting with "#  --"
    env_file_content
        .lines() // Split into lines
        .filter(|line| !line.starts_with("# sign:"))
        .filter(|line| !line.starts_with("#sign:"))
        .collect::<Vec<_>>() // Collect remaining lines into a Vec
        .join("\n")
}

pub fn construct_front_matter() -> String {
    let env_file_uuid = uuid::Uuid::now_v7().to_string();
    format!("# ---\n# uuid: {env_file_uuid}\n# ---\n\n")
}

pub fn sign_and_update_env_file_content(
    private_key: &str,
    env_file_content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let new_content =
        if !(env_file_content.starts_with("# ---") || env_file_content.starts_with("#---")) {
            // append front matter for signature
            let front_matter = construct_front_matter();
            format!("{front_matter}{env_file_content}")
        } else {
            env_file_content.to_string()
        };
    let message = remove_signature(&new_content);
    let signature = sign_message(private_key, &message)?;
    Ok(update_signature(&new_content, &signature))
}

pub fn update_signature(env_file_content: &str, signature: &str) -> String {
    // remove existing signature line
    let new_content = remove_signature(env_file_content);
    let new_signature = format!("# sign: {signature}");
    // check front matter or not
    if new_content.starts_with("# ---") || new_content.starts_with("#---") {
        let mut lines = new_content.lines().collect::<Vec<_>>();
        // Find index of "# ---" or "#---" from lines
        let index = lines[1..]
            .iter()
            .position(|&line| line.starts_with("# ---") || line.starts_with("#---"));
        if let Some(idx) = index {
            // Insert the signature line before the end marker
            lines.insert(idx + 1, &new_signature);
        } else {
            // If no end marker found, append the signature as second line
            lines.insert(1, &new_signature);
        }
        lines.join("\n")
    } else {
        env_file_content.to_string()
    }
}

impl EnvFile {
    pub fn encrypt(
        &self,
        public_key: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut encrypted_entries: HashMap<String, String> = HashMap::new();
        for (key, value) in &self.entries {
            if !value.starts_with("encrypted:") {
                let encrypted_value = encrypt_env_item(public_key, value)?;
                encrypted_entries.insert(key.clone(), encrypted_value);
            } else {
                encrypted_entries.insert(key.clone(), value.clone());
            }
        }
        Ok(encrypted_entries)
    }

    pub fn decrypt(
        &self,
        private_key: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut decrypted_entries: HashMap<String, String> = HashMap::new();
        for (key, value) in &self.entries {
            if value.starts_with("encrypted:") {
                let decrypted_value = decrypt_env_item(private_key, value)?;
                decrypted_entries.insert(key.clone(), decrypted_value);
            } else {
                decrypted_entries.insert(key.clone(), value.clone());
            }
        }
        Ok(decrypted_entries)
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::crypt_util::{sign_message, verify_signature};
    use crate::commands::model::DotenvxKeyStore;

    #[test]
    fn test_from_file() {
        let env_file = super::EnvFile::from(".env.example").unwrap();
        println!("{env_file:?}");
    }

    #[test]
    fn test_global() {
        let store = DotenvxKeyStore::load_global().unwrap();
        println!("{store:?}");
    }

    #[test]
    fn test_generate_signature() {
        let private_key = "9e70188d351c25d0714929205df9b8f4564b6b859966bdae7aef7f752a749d8b";
        let env_file_content = std::fs::read_to_string(".env").unwrap();
        let message = super::remove_signature(&env_file_content);
        let signature = sign_message(private_key, &message).unwrap();
        println!("{signature}");
    }

    #[test]
    fn test_verify_file_signature() {
        let public_key = "02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0";
        let env_file_content = std::fs::read_to_string(".env").unwrap();
        let signature = super::get_signature(&env_file_content).unwrap();
        let message = super::remove_signature(&env_file_content);
        let result = verify_signature(public_key, &message, &signature).unwrap();
        assert!(result, "Signature verification failed");
    }

    #[test]
    fn test_get_signature() {
        let public_key = "039dd52f537a84a560fd18600ff40856f3bfcc103e70f329acc21327622042b195";
        let private_key = "a3d15e4b69c4a942c3813ba6085542ff6db1189378596d2f8a8652c550b7dea6";
        let content = std::fs::read_to_string(".env.example").unwrap().to_string();
        let signature = if let Some(signature) = super::get_signature(&content) {
            signature
        } else {
            sign_message(private_key, &content).unwrap()
        };
        // update the content with the signature
        let updated_content = super::update_signature(&content, &signature);
        let signature_2 = super::get_signature(&updated_content).unwrap();
        assert_eq!(signature, signature_2, "Signature mismatch");
        let content_2 = super::remove_signature(&updated_content);
        let result = verify_signature(public_key, &content_2, &signature_2).unwrap();
        assert!(result, "Signature verification failed");
    }

    #[test]
    fn test_update_signature() {
        let content = std::fs::read_to_string(".env.example").unwrap();
        let updated_content = super::update_signature(&content, "your_signature_here");
        println!("{updated_content}");
    }
}
