use clap::ArgMatches;
use colored::Colorize;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

pub mod decrypt;
pub mod encrypt;
pub mod keypair;
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
        let entries = read_dotenv_file(&dotenv_file_path)?;
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
    // create a new private key if not found
    let key_pair = EcKeyPair::generate();
    let private_key_hex = key_pair.get_sk_hex();
    write_private_key_to_file(dotenv_file_path, &env_key_name, &private_key_hex)?;
    Ok(private_key_hex)
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
    // get public key from the default private key
    let private_key_hex = get_private_key(profile_name)?;
    let kp = EcKeyPair::from_secret_key(&private_key_hex);
    Ok(kp.get_pk_hex())
}

pub fn write_public_key_to_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let header_text = format!(
        r#"
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY="{}"
"#,
        public_key
    );
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    // file does not exist, and we create it
    if !env_file.as_ref().exists() {
        fs::write(&env_file, header_text.as_bytes())?;
        println!(
            "{}",
            format!("✔ {} file created with the public key", file_name).green()
        );
        return Ok(());
    } else {
        let env_file_content = fs::read_to_string(&env_file).unwrap();
        if !env_file_content.contains("DOTENV_PUBLIC_KEY") {
            let file_content = format!("{}\n{}", header_text.trim(), env_file_content);
            fs::write(&env_file, file_content.as_bytes())?;
            println!("{}", format!("✔ public key added in {}", file_name).green());
        } else if !env_file_content.contains(public_key) {
            // update existing public key
            let mut new_content = String::new();
            for line in env_file_content.lines() {
                if line.starts_with("DOTENV_PUBLIC_KEY") {
                    new_content.push_str(&format!("DOTENV_PUBLIC_KEY=\"{}\"\n", public_key));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            fs::write(&env_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ public key updated in {}", file_name).green()
            );
        } else {
            println!(
                "{}",
                format!("✔ public key already exists in {}", file_name).green()
            );
        }
    }
    Ok(())
}

pub fn write_private_key_to_file<P: AsRef<Path>>(
    env_keys_file: P,
    private_key_name: &str,
    private_key_value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/

{}="{}"
"#,
            private_key_name, private_key_value
        );
        fs::write(&env_keys_file, file_content.as_bytes())?;
        println!(
            "{}",
            format!("✔ {} file created with the private key", file_name).green()
        );
    } else {
        let env_keys_content = fs::read_to_string(&env_keys_file).unwrap();
        // no key in the file, we add it
        if !env_keys_content.contains(private_key_name) {
            let new_content = format!(
                "{}\n{}=\"{}\"\n",
                env_keys_content.trim(),
                private_key_name,
                private_key_value
            );
            fs::write(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key added in {}", file_name).green()
            );
        } else if !env_keys_content.contains(private_key_value) {
            // update existing private key
            let mut new_content = String::new();
            for line in env_keys_content.lines() {
                if line.starts_with(&format!("{}=", private_key_name)) {
                    new_content
                        .push_str(&format!("{}=\"{}\"\n", private_key_name, private_key_value));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            fs::write(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key updated in {}", file_name).green()
            );
        } else {
            println!(
                "{}",
                format!("✔ private key already exists in {}", file_name).green()
            );
        }
    }
    Ok(())
}

pub fn get_env_file_arg(command_matches: &ArgMatches) -> String {
    if let Some(arg_value) = command_matches.get_one::<String>("env-file") {
        arg_value.clone()
    } else {
        ".env".to_string()
    }
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

    #[test]
    fn test_write_public_key() {
        let public_key = "xxxx";
        let env_file = PathBuf::from(".env.test");
        write_public_key_to_file(&env_file, public_key).unwrap();
    }

    #[test]
    fn test_write_private_key() {
        let env_file = PathBuf::from(".env.keys");
        write_private_key_to_file(&env_file, "DOTENV_PRIVATE_KEY_TEST", "xxxx").unwrap();
    }
}
