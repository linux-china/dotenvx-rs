use crate::commands::crypt_util::{decrypt_env_item, encrypt_env_item};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

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
        if let Ok(entries) = read_dotenv_content(&content) {
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

pub fn read_dotenv_content(
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

pub fn remove_signature(env_file_content: &str) -> String {
    // Remove lines starting with "#  --"
    env_file_content
        .lines() // Split into lines
        .filter(|line| !line.starts_with("# signature:"))
        .filter(|line| !line.starts_with("#signature:"))
        .collect::<Vec<_>>() // Collect remaining lines into a Vec
        .join("\n")
}

pub fn update_signature(env_file_content: &str, signature: &str) -> String {
    // remove existing signature line
    let new_content = remove_signature(env_file_content);
    let new_signature = format!("# signature: {signature}");
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
        format!("# ---\n{new_signature}\n# ---\n\n{new_content}")
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
    #[test]
    fn test_from_file() {
        let env_file = super::EnvFile::from(".env.example").unwrap();
        println!("{env_file:?}");
    }

    #[test]
    fn test_update_signature() {
        let content = std::fs::read_to_string(".env.example").unwrap();
        let updated_content = super::update_signature(&content, "your_signature_here");
        println!("{updated_content}");
    }
}
