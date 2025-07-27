use crate::commands::crypt_util::EcKeyPair;
use clap::ArgMatches;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_file;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

pub mod crypt_util;
pub mod decrypt;
pub mod diff;
pub mod encrypt;
pub mod get_cmd;
pub mod init;
pub mod keypair;
pub mod list;
mod model;
pub mod rotate;
pub mod run;
pub mod set_cmd;
pub mod verify;

const KEYS_FILE_NAME: &str = ".env.keys";

pub fn read_dotenv_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    for (key, value) in dotenvy::from_filename_iter(path)?.flatten() {
        entries.insert(key.clone(), value.clone());
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
    let dotenv_keys_file_path = find_dotenv_keys_file();
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
    let env_file_name = if let Some(name) = profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_string()
    };
    let dotenv_file_path = find_env_file_path(&env::current_dir()?, &env_file_name)
        .unwrap_or_else(|| PathBuf::from(env_file_name));
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
    let header_text = construct_env_file_header(&env_pub_key_name, public_key);
    if env_file.as_ref().exists() {
        let file_content = fs::read_to_string(&env_file).unwrap();
        if !file_content.contains(&env_pub_key_name) {
            let file_content = format!("{}\n{}", header_text.trim(), file_content);
            fs::write(&env_file, file_content.as_bytes()).unwrap();
            println!(
                "{}",
                format!("✔ A new public key added in {file_name} file").green()
            );
        }
    } else {
        let file_content = if let Some(pairs) = pairs {
            format!("{}\n{}", header_text.trim(), pairs)
        } else {
            header_text
        };
        fs::write(&env_file, file_content.trim_start().as_bytes()).unwrap();
    }
}

pub fn construct_env_file_header(env_pub_key_name: &str, public_key: &str) -> String {
    let env_file_uuid = uuid::Uuid::now_v7().to_string();
    format!(
        r#"
# ---
# id: {}
# name: your project name
# group: com.example.project_group
# ---
{}="{}"

# Environment variables. MAKE SURE to ENCRYPT them before committing to source control
"#,
        &env_file_uuid, &env_pub_key_name, public_key
    )
}

pub fn write_public_key_to_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_short = public_key.chars().take(8).collect::<String>();
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let header_text = construct_env_file_header(&env_pub_key_name, public_key);
    // file does not exist, and we create it
    if !env_file.as_ref().exists() {
        fs::write(&env_file, header_text.trim_start().as_bytes())?;
        println!(
            "{}",
            format!("✔ {file_name} file created with the public key").green()
        );
        return Ok(());
    } else {
        let env_file_content = fs::read_to_string(&env_file).unwrap();
        if !env_file_content.contains(&env_pub_key_name) {
            let file_content = format!("{}\n{}", header_text.trim(), env_file_content);
            fs::write(&env_file, file_content.as_bytes())?;
            println!("{}", format!("✔ public key added in {file_name}").green());
        } else if !env_file_content.contains(public_key) {
            // update existing public key
            let mut new_content = String::new();
            for line in env_file_content.lines() {
                if line.starts_with(&env_pub_key_name) {
                    new_content.push_str(&format!("{env_pub_key_name}=\"{public_key}\"\n"));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            fs::write(&env_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ public key({public_key_short}...) updated in {file_name}").green()
            );
        } else {
            println!(
                "{}",
                format!("✔ public key({public_key_short}...) already exists in {file_name}")
                    .green()
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
    let keys_file_uuid = uuid::Uuid::now_v7().to_string();
    let private_key_short = private_key_value.chars().take(6).collect::<String>();
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
# ---
# id: {keys_file_uuid}
# name: input your name here
# group: demo
# ---

#  Private decryption keys. DO NOT commit to source control
{private_key_name}="{private_key_value}"
"#
        );
        fs::write(&env_keys_file, file_content.trim_start().as_bytes())?;

        println!(
            "{}",
            format!("✔ {file_name} file created with the private key({private_key_short}...)")
                .green()
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
                format!("✔ private key({private_key_short}...) added in {file_name}").green()
            );
        } else if !env_keys_content.contains(private_key_value) {
            // update existing private key
            let mut new_content = String::new();
            for line in env_keys_content.lines() {
                if line.starts_with(&format!("{private_key_name}=")) {
                    new_content.push_str(&format!("{private_key_name}=\"{private_key_value}\"\n"));
                } else {
                    new_content.push_str(line);
                    new_content.push('\n');
                }
            }
            fs::write(&env_keys_file, new_content.as_bytes())?;
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) updated in {file_name}").green()
            );
        } else {
            println!(
                "{}",
                format!("✔ private key({private_key_short}...) already exists in {file_name}")
                    .green()
            );
        }
    }
    Ok(())
}

pub fn get_env_file_arg(command_matches: &ArgMatches, profile: &Option<String>) -> String {
    if let Some(arg_value) = command_matches.get_one::<String>("env-file") {
        arg_value.clone()
    } else if let Some(profile_name) = profile {
        format!(".env.{profile_name}")
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
        wrapped_value = format!("\"{wrapped_value}\"");
    }
    wrapped_value
}

pub fn append_to_ignores(file_name: &str) {
    // git repository but no .gitignore file
    if Path::new(".git").exists() && !Path::new(".gitignore").exists() {
        fs::write(".gitignore", format!("{file_name}\n")).unwrap();
    }
    let ignore_files = [".gitignore", ".dockerignore", ".aiignore"];
    for ignore_file in &ignore_files {
        let path = PathBuf::from(ignore_file);
        if path.exists() {
            let mut content = fs::read_to_string(&path).unwrap_or_default();
            if !content.contains(format!("{file_name}\n").as_str()) {
                content.push_str(&format!("\n{file_name}"));
                fs::write(&path, content).expect("Failed to write to ignore file");
                println!(
                    "{}",
                    format!("✔ {file_name} added to {ignore_file}").green()
                );
            } else {
                println!(
                    "{}",
                    format!("✔ {file_name} already exists in {ignore_file}").green()
                );
            }
        }
    }
}

/// Finds the `.env.keys` file in the current directory or its parent directories.
pub fn find_dotenv_keys_file() -> Option<PathBuf> {
    let current_dir = env::current_dir().unwrap();
    find_dotenv_keys_file_by_path(&current_dir)
}

pub fn find_dotenv_keys_file_by_path(dir: &Path) -> Option<PathBuf> {
    if dir.join(KEYS_FILE_NAME).exists() {
        return Some(dir.join(KEYS_FILE_NAME));
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
