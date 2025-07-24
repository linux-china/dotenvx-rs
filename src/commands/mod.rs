use clap::ArgMatches;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_file;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

pub mod decrypt;
pub mod encrypt;
pub mod get_cmd;
pub mod init;
pub mod keypair;
pub mod list;
pub mod rotate;
pub mod run;
pub mod set_cmd;

const KEYS_FILE_NAME: &str = ".env.keys";

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

    pub fn get_pk_hex(&self) -> String {
        let pk_compressed_bytes = self.public_key.serialize_compressed();
        hex::encode(pk_compressed_bytes)
    }

    pub fn get_sk_hex(&self) -> String {
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

pub fn get_private_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    get_private_key(&profile_name)
}

pub fn get_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_private_key_name(profile_name);
    let dotenv_keys_file_path = find_dotenv_keys_file_path(&env::current_dir()?);
    let key_entries = if let Some(file_path) = &dotenv_keys_file_path {
        read_dotenv_file(file_path)?
    } else {
        HashMap::new()
    };
    // read from .env.keys file
    if let Some(val) = key_entries.get(&env_key_name) {
        return Ok(val.trim_matches('"').to_owned());
    }
    // read from environment variables
    if let Ok(private_key) = env::var(&env_key_name) {
        return Ok(private_key);
    }
    // create a new private key if not found
    let key_pair = EcKeyPair::generate();
    let private_key_hex = key_pair.get_sk_hex();
    if let Some(file_path) = &dotenv_keys_file_path {
        write_private_key_to_file(file_path, &env_key_name, &private_key_hex)?;
    } else {
        // if .env.keys file not found, create it in the current directory
        let file_path = PathBuf::from(KEYS_FILE_NAME);
        write_private_key_to_file(&file_path, &env_key_name, &private_key_hex)?;
    }
    Ok(private_key_hex)
}

pub fn get_public_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    get_public_key(&profile_name)
}

pub fn get_public_key(profile_name: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_public_key_name(profile_name);
    let dotenv_file_path = if let Some(name) = profile_name {
        PathBuf::from(format!(".env.{}", name))
    } else {
        PathBuf::from(".env")
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
    let private_key_hex = get_private_key(profile_name)?;
    let kp = EcKeyPair::from_secret_key(&private_key_hex);
    Ok(kp.get_pk_hex())
}

pub fn create_env_file<P: AsRef<Path>>(env_file: P, public_key: &str, pairs: Option<&str>) {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let header_text = format!(
        r#"
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
{}="{}"

# env variables
{}
"#,
        &env_pub_key_name,
        public_key,
        pairs.unwrap_or("")
    );
    fs::write(env_file, header_text.trim_start().as_bytes()).unwrap();
}

pub fn write_public_key_to_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let header_text = format!(
        r#"
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
{}="{}"

# env variables
"#,
        &env_pub_key_name, public_key
    );
    // file does not exist, and we create it
    if !env_file.as_ref().exists() {
        fs::write(&env_file, header_text.trim_start().as_bytes())?;
        println!(
            "{}",
            format!("✔ {} file created with the public key", file_name).green()
        );
        return Ok(());
    } else {
        let env_file_content = fs::read_to_string(&env_file).unwrap();
        if !env_file_content.contains(&env_pub_key_name) {
            let file_content = format!("{}\n{}", header_text.trim(), env_file_content);
            fs::write(&env_file, file_content.as_bytes())?;
            println!("{}", format!("✔ public key added in {}", file_name).green());
        } else if !env_file_content.contains(public_key) {
            // update existing public key
            let mut new_content = String::new();
            for line in env_file_content.lines() {
                if line.starts_with(&env_pub_key_name) {
                    new_content.push_str(&format!("{}=\"{}\"\n", env_pub_key_name, public_key));
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
#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/

{}="{}"
"#,
            private_key_name, private_key_value
        );
        fs::write(&env_keys_file, file_content.trim_start().as_bytes())?;
        println!(
            "{}",
            format!("✔ {} file created with the private key", file_name).green()
        );
        append_to_ignores(KEYS_FILE_NAME);
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

pub fn get_profile_arg(command_matches: &ArgMatches) -> String {
    if let Some(arg_value) = command_matches.get_one::<String>("profile") {
        arg_value.clone()
    } else {
        ".env".to_string()
    }
}

pub fn get_env_file_arg(command_matches: &ArgMatches) -> String {
    if let Some(arg_value) = command_matches.get_one::<String>("env-file") {
        arg_value.clone()
    } else if let Some(profile_name) = command_matches.get_one::<String>("profile") {
        format!(".env.{}", profile_name)
    } else {
        ".env".to_string()
    }
}

pub fn get_public_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    }
}

pub fn get_private_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
}

pub fn get_public_key_name_for_file(env_file: &str) -> String {
    if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    }
}

pub fn get_private_key_name_for_file(env_file: &str) -> String {
    if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
}

pub fn wrap_shell_value(value: &str) -> String {
    let mut wrapped_value = value.to_string();
    let mut double_quote_required = false;
    if wrapped_value.contains("\n") {
        wrapped_value = wrapped_value.replace("\n", "\\n");
        double_quote_required = true;
    }
    if wrapped_value.contains("\"") {
        wrapped_value = wrapped_value.replace('"', "\\\"");
        double_quote_required = true;
    }
    if wrapped_value.contains(' ') {
        double_quote_required = true;
    }
    if double_quote_required {
        wrapped_value = format!("\"{}\"", wrapped_value);
    }
    wrapped_value
}

pub fn append_to_ignores(file_name: &str) {
    // git repository but no .gitignore file
    if Path::new(".git").exists() && !Path::new(".gitignore").exists() {
        fs::write(".gitignore", format!("{}\n", file_name)).unwrap();
    }
    let ignore_files = [".gitignore", ".dockerignore", ".aiignore"];
    for ignore_file in &ignore_files {
        let path = PathBuf::from(ignore_file);
        if path.exists() {
            let mut content = fs::read_to_string(&path).unwrap_or_default();
            if !content.contains(format!("{}\n", file_name).as_str()) {
                content.push_str(&format!("\n{}", file_name));
                fs::write(&path, content).expect("Failed to write to ignore file");
                println!(
                    "{}",
                    format!("✔ {} added to {}", file_name, ignore_file).green()
                );
            } else {
                println!(
                    "{}",
                    format!("✔ {} already exists in {}", file_name, ignore_file).green()
                );
            }
        }
    }
}

pub fn find_dotenv_keys_file_path(dir: &Path) -> Option<PathBuf> {
    if dir.join(KEYS_FILE_NAME).exists() {
        return Some(dir.join(KEYS_FILE_NAME));
    } else if let Some(parent) = dir.parent() {
        return find_dotenv_keys_file_path(parent);
    }
    None
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
        let env_file = PathBuf::from(KEYS_FILE_NAME);
        write_private_key_to_file(&env_file, "DOTENV_PRIVATE_KEY_TEST", "xxxx").unwrap();
    }
}
