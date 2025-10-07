use crate::commands::crypt_util::EcKeyPair;
use crate::commands::framework::detect_framework;
use crate::commands::model::{DotenvxKeyStore, KeyPair};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use csv::WriterBuilder;
use dotenvx_rs::common::{find_dotenv_keys_file, find_env_file_path, get_profile_name_from_file};
use java_properties::PropertiesIter;
use reqwest::blocking::Client;
use reqwest::header;
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::{env, fs, io};
use walkdir::DirEntry;

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

pub mod cloud;
pub mod completion;
pub mod doctor;
pub mod dotenvx_cloud;
pub mod framework;
pub mod link;
pub mod linter;

const KEYS_FILE_NAME: &str = ".env.keys";

pub fn get_dotenvx_home() -> PathBuf {
    dirs::home_dir().unwrap().join(".dotenvx")
}

pub fn is_sensitive_key(key_name: &str) -> bool {
    let encrypted_patterns = [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "KEY",
        "PRIVATE",
        "CREDENTIAL",
    ];
    for encrypted_pattern in encrypted_patterns {
        if key_name.contains(encrypted_pattern) {
            return true;
        }
    }
    false
}

pub fn find_private_key_from_home(public_key_hex: &str) -> Option<String> {
    if let Ok(key_store) = DotenvxKeyStore::load_global() {
        key_store.find_private_key(public_key_hex);
    }
    None
}

pub fn find_all_keys() -> HashMap<String, KeyPair> {
    if let Ok(key_store) = DotenvxKeyStore::load_global() {
        key_store.keys.clone()
    } else {
        HashMap::new()
    }
}

pub fn write_key_pair(key_pair: &KeyPair) -> anyhow::Result<()> {
    let mut key_store = if let Ok(store) = DotenvxKeyStore::load_global() {
        store
    } else {
        DotenvxKeyStore::new()
    };
    if !key_store.keys.contains_key(&key_pair.public_key) {
        key_store
            .keys
            .insert(key_pair.public_key.clone(), key_pair.clone());
        return key_store.write();
    }
    Ok(())
}

pub fn write_key_pairs(key_pairs: &Vec<KeyPair>) -> anyhow::Result<()> {
    let mut key_store = if let Ok(store) = DotenvxKeyStore::load_global() {
        store
    } else {
        DotenvxKeyStore::new()
    };
    let mut is_changed = false;
    for key_pair in key_pairs {
        if !key_store.keys.contains_key(&key_pair.public_key) {
            is_changed = true;
            key_store
                .keys
                .insert(key_pair.public_key.clone(), key_pair.clone());
        }
    }
    if is_changed {
        return key_store.write();
    }
    Ok(())
}

pub fn read_dotenv_file<P: AsRef<Path>>(
    path: P,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    let file_name = path.as_ref().file_name().and_then(|s| s.to_str()).unwrap();
    if file_name.ends_with(".properties") {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        PropertiesIter::new(reader)
            .read_into(|key, value| {
                entries.insert(key, value);
            })
            .unwrap();
    } else {
        for (key, value) in dotenvy::from_filename_iter(path)?.flatten() {
            entries.insert(key.clone(), value.clone());
        }
    }
    Ok(entries)
}

pub fn read_dotenv_url(
    file_url: &str,
    headers: Option<HashMap<String, String>>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries: HashMap<String, String> = HashMap::new();
    let body = read_content_from_dotenv_url(file_url, headers)?;
    let reader = io::Cursor::new(body.into_bytes());
    for (key, value) in dotenvy::from_read_iter(reader).flatten() {
        entries.insert(key.clone(), value.clone());
    }
    Ok(entries)
}

pub fn read_content_from_dotenv_url(
    file_url: &str,
    headers: Option<HashMap<String, String>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut request_headers = header::HeaderMap::new();
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            request_headers.insert(
                header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                header::HeaderValue::from_str(&value).unwrap(),
            );
        }
    }
    let response = client.get(file_url).headers(request_headers).send()?;
    if response.status().is_success() {
        let body = response.text()?;
        Ok(body)
    } else {
        Err(format!(
            "Failed to fetch dotenv file from URL: {}. Status: {}",
            file_url,
            response.status()
        )
        .into())
    }
}

pub fn get_private_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let public_key = get_public_key_for_file(env_file)?;
    if !public_key.is_empty()
        && let Some(private_key) = find_private_key_from_home(&public_key)
    {
        return Ok(private_key);
    }
    let profile_name = get_profile_name_from_file(env_file);
    get_private_key(&profile_name)
}

pub fn get_private_key(
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_private_key_name(profile_name);
    let dotenv_keys_file_path = if let Some(profile) = profile_name
        && profile.starts_with("g_")
    {
        dirs::home_dir().map(|home| home.join(KEYS_FILE_NAME))
    } else {
        find_dotenv_keys_file()
    };
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
    let public_key_hex = key_pair.get_pk_hex();
    let private_key_hex = key_pair.get_sk_hex();
    let key_pair = KeyPair::new(&public_key_hex, &private_key_hex, profile_name);
    if let Some(file_path) = &dotenv_keys_file_path {
        write_private_key_to_file(file_path, &env_key_name, &key_pair)?;
    } else {
        // if .env.keys file not found, create it in the current directory
        let file_path = PathBuf::from(KEYS_FILE_NAME);
        write_private_key_to_file(&file_path, &env_key_name, &key_pair)?;
    }
    Ok(private_key_hex)
}

pub fn get_public_key_for_file(env_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile_name = get_profile_name_from_file(env_file);
    if env_file.ends_with(".properties") {
        let file_content = fs::read_to_string(env_file).unwrap();
        for line in file_content.lines() {
            if line.starts_with("dotenv.public.key") {
                return line
                    .split('=')
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .ok_or_else(|| "Public key not found in properties file".into());
            }
        }
    }
    get_public_key(&profile_name)
}

pub fn get_public_key(profile_name: &Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let env_key_name = get_public_key_name(profile_name);
    let env_file_name = if let Some(name) = profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_string()
    };
    let dotenv_file_path = if let Some(profile) = profile_name
        && profile.starts_with("g_")
    {
        dirs::home_dir()
            .unwrap()
            .join(".dotenvx")
            .join(env_file_name)
    } else {
        find_env_file_path(&env::current_dir()?, &env_file_name)
            .unwrap_or_else(|| PathBuf::from(env_file_name))
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

pub fn get_public_key_from_text_file(file_path: &str) -> Option<String> {
    if Path::new(file_path).exists() {
        if let Ok(content) = fs::read_to_string(file_path) {
            // extract the public key by text parsing
            for line in content.lines() {
                let line = line.trim();
                if line.contains("dotenv.public.key") || line.contains("DOTENV_PUBLIC_KEY") {
                    let result = line
                        .split(['=', ':', '：'])
                        .nth(1)
                        .map(|s| s.trim().to_string())
                        .map(|s| {
                            s.split([',', ';', '}', ']', ')', ' ', '-', '_'])
                                .next()
                                .unwrap()
                                .trim()
                                .to_string()
                        })
                        .map(|s| s.trim_matches(['"', '\'']).to_string())
                        .filter(|s| s.len() == 66);
                    if result.is_some() {
                        return result;
                    }
                }
            }
            if file_path.ends_with(".json") {
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Ok(pretty_json_text) = serde_json::to_string_pretty(&json_value) {
                        for line in pretty_json_text.lines() {
                            let line = line.trim();
                            if line.contains("dotenv.public.key")
                                || line.contains("DOTENV_PUBLIC_KEY")
                            {
                                let result = line
                                    .split([':'])
                                    .nth(1)
                                    .map(|s| s.trim().to_string())
                                    .map(|s| {
                                        s.split([',', ';', '}', ']', ')', ' ', '-', '_'])
                                            .next()
                                            .unwrap()
                                            .trim()
                                            .to_string()
                                    })
                                    .map(|s| s.trim_matches(['"', '\'']).to_string())
                                    .filter(|s| s.len() == 66);
                                if result.is_some() {
                                    return result;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn create_env_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
    pairs: Option<&str>,
    group: &Option<String>,
    name: &Option<String>,
) {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let mut env_pub_key_name = get_public_key_name(&profile_name);
    if file_name.ends_with(".properties") {
        env_pub_key_name = env_pub_key_name
            .to_lowercase()
            .replace('_', ".")
            .to_string();
    }
    let header_text = if file_name.ends_with(".properties") && env_file.as_ref().exists() {
        let mut app_name: Option<String> = group.clone();
        let mut app_group: Option<String> = name.clone();
        let f = File::open(&env_file).unwrap();
        let reader = BufReader::new(f);
        PropertiesIter::new(reader)
            .read_into(|key, value| {
                if key == "spring.application.name" {
                    app_name = Some(value);
                } else if key == "spring.application.group" {
                    app_group = Some(value);
                }
            })
            .unwrap();
        construct_env_file_header(&env_pub_key_name, public_key, &app_group, &app_name)
    } else {
        construct_env_file_header(&env_pub_key_name, public_key, group, name)
    };
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
        // create parent directory if it does not exist
        if let Some(parent_dir) = env_file.as_ref().parent() {
            if !parent_dir.exists() {
                fs::create_dir_all(parent_dir).unwrap();
            }
        }
        if file_content.ends_with("\n") {
            fs::write(&env_file, file_content.trim_start().as_bytes()).unwrap();
        } else {
            fs::write(
                &env_file,
                format!("{}\n", file_content.trim_start()).as_bytes(),
            )
            .unwrap();
        }
    }
}

pub fn update_env_file<P: AsRef<Path>>(env_file: P, public_key: &str, content: &str) {
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    if (file_name.ends_with(".properties") && !content.contains("dotenv.public.key"))
        || (file_name.starts_with(".env") && !content.contains("DOTENV_PUBLIC_KEY"))
    {
        let header = construct_env_file_header(
            &get_public_key_name_for_file(file_name),
            public_key,
            &None,
            &None,
        );
        let new_content = format!("{}\n{}\n", header.trim(), content.trim());
        fs::write(&env_file, new_content).unwrap();
    } else if content.ends_with("\n") {
        fs::write(&env_file, content).unwrap();
    } else {
        fs::write(&env_file, format!("{content}\n")).unwrap();
    }
}

pub fn construct_env_file_header(
    env_pub_key_name: &str,
    public_key: &str,
    group: &Option<String>,
    name: &Option<String>,
) -> String {
    let env_file_uuid = uuid::Uuid::now_v7().to_string();
    format!(
        r#"
# ---
# uuid: {}
# name: {}
# group: {}
# ---
{}={}

# Environment variables. MAKE SURE to ENCRYPT them before committing to source control
"#,
        &env_file_uuid,
        name.clone().unwrap_or("project_ame".to_owned()),
        group.clone().unwrap_or("group_name".to_owned()),
        &env_pub_key_name,
        public_key
    )
    .trim()
    .to_string()
}

pub fn write_public_key_to_file<P: AsRef<Path>>(
    env_file: P,
    public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_short = public_key.chars().take(8).collect::<String>();
    let file_name = env_file.as_ref().file_name().unwrap().to_str().unwrap();
    let profile_name = get_profile_name_from_file(file_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let header_text = construct_env_file_header(&env_pub_key_name, public_key, &None, &None);
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
    key_pair: &KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys_file_uuid = uuid::Uuid::now_v7().to_string();
    let private_key_value = &key_pair.private_key;
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
# uuid: {keys_file_uuid}
# name: {}
# group: {}
# ---

#  Private decryption keys. DO NOT commit to source control
{}={}
"#,
            &key_pair.name.clone().unwrap_or("project_name".to_string()),
            key_pair.group.clone().unwrap_or("group_name".to_string()),
            private_key_name,
            private_key_value
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
                "{}\n{}={}\n",
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
            if let Some(parent_dir) = env_keys_file.as_ref().parent() {
                if !parent_dir.exists() {
                    fs::create_dir_all(parent_dir).unwrap();
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
    // write the key pairs to global
    write_key_pair(key_pair)?;
    Ok(())
}

pub fn get_env_file_arg(command_matches: &ArgMatches, profile: &Option<String>) -> String {
    let env_file_arg = command_matches.get_one::<String>("env-file");
    // specified .env file argument takes precedence
    if let Some(env_file) = env_file_arg {
        return env_file.clone();
    }
    // load env file by profile
    let dotenv_file = if let Some(profile_name) = profile {
        if profile_name.starts_with("g_") {
            let dotenvx_home = dirs::home_dir().unwrap().join(".dotenvx");
            format!("{}/.env.{profile_name}", dotenvx_home.display())
        } else {
            format!(".env.{profile_name}")
        }
    } else {
        ".env".to_string()
    };
    // if the file does not exist in the current dir, we try to detect it
    if !Path::new(&dotenv_file).exists() {
        // detect other files
        let properties_file = if let Some(profile_name) = profile {
            format!("application-{profile_name}.properties")
        } else {
            "application.properties".to_string()
        };
        if Path::new(&properties_file).exists() {
            return properties_file;
        }
        // detect framework
        if let Some(framework) = detect_framework() {
            if framework == "spring-boot" {
                let properties_file = if let Some(profile_name) = profile {
                    format!("src/main/resources/application-{profile_name}.properties")
                } else {
                    "src/main/resources/application.properties".to_string()
                };
                if Path::new(&properties_file).exists() {
                    return properties_file;
                }
            } else if framework == "gofr" {
                let env_file = if let Some(profile_name) = profile {
                    format!("configs/.env.{profile_name}")
                } else {
                    "configs/.env".to_string()
                };
                if Path::new(&env_file).exists() {
                    return env_file;
                }
            }
        }
    }
    dotenv_file
}

pub fn get_public_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    }
}

pub fn is_public_key_name(key: &str) -> bool {
    key.starts_with("DOTENV_PUBLIC_KEY") || key.starts_with("dotenv.public.key")
}

pub fn is_public_key_included(file_content: &str) -> bool {
    file_content.contains("DOTENV_PUBLIC_KEY") || file_content.contains("dotenv.public.key")
}

pub fn get_private_key_name(profile_name: &Option<String>) -> String {
    if let Some(name) = profile_name {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
}

pub fn get_public_key_name_for_file(env_file: &str) -> String {
    let public_key_name = if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PUBLIC_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PUBLIC_KEY".to_string()
    };
    if env_file.ends_with(".properties") {
        public_key_name.to_lowercase().replace('_', ".")
    } else {
        public_key_name
    }
}

pub fn get_private_key_name_for_file(env_file: &str) -> String {
    if let Some(name) = get_profile_name_from_file(env_file) {
        format!("DOTENV_PRIVATE_KEY_{}", name.to_uppercase())
    } else {
        "DOTENV_PRIVATE_KEY".to_string()
    }
}

pub fn adjust_env_key(key: &str, env_file: &str) -> String {
    if !env_file.contains(".properties") {
        key.replace(['-', '.'], "_").to_uppercase()
    } else {
        key.to_string()
    }
}
pub fn escape_shell_value(value: &str) -> String {
    use shlex::try_quote;
    if let Ok(escaped_value) = try_quote(value) {
        escaped_value.to_string()
    } else {
        value.to_string()
    }
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

pub fn list_env_files<P: AsRef<Path>>(
    root: P,
    max_depth: usize,
    profile: &Option<String>,
) -> Vec<DirEntry> {
    walkdir::WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let file_name = e.file_name().to_str().unwrap();
            if file_name == ".env.keys" || file_name == ".env.vault" {
                false
            } else {
                file_name.starts_with(".env.") || file_name == ".env"
            }
        })
        .filter(|e| {
            // filter by profile if provided
            let file_name = e.file_name().to_str().unwrap();
            if let Some(profile_name) = profile {
                let env_file_name = format!(".env.{profile_name}");
                file_name.starts_with(&env_file_name)
            } else {
                true
            }
        })
        .collect()
}

pub fn std_output(entries: &HashMap<String, String>, format: &Option<&String>) {
    if let Some(fmt) = format {
        if *fmt == "json" {
            let json_value = json!(entries);
            println!("{}", to_colored_json_auto(&json_value).unwrap());
        } else if *fmt == "shell" {
            for (key, value) in entries {
                println!("export {}={}", key, escape_shell_value(value));
            }
        } else if *fmt == "csv" {
            let mut wtr = WriterBuilder::new()
                .delimiter(b',') // Use semicolon as delimiter
                .terminator(csv::Terminator::CRLF) // Use CRLF for line endings
                .from_writer(io::stdout());
            wtr.write_record(["key", "value"]).unwrap();
            for (key, value) in entries {
                wtr.write_record([key, value]).unwrap();
            }
            wtr.flush().unwrap();
        } else if *fmt == "raw" {
            for value in entries.values() {
                println!("{value}");
            }
        } else {
            for (key, value) in entries {
                println!("{}={}", key, escape_shell_value(value));
            }
        }
    }
}

pub fn is_remote_env_file(env_file: &str) -> bool {
    env_file.starts_with("http://") || env_file.starts_with("https://")
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
        let key_pair = KeyPair::new("xxxx", "yyyyy", &None);
        write_private_key_to_file(&env_file, "DOTENV_PRIVATE_KEY_TEST", &key_pair).unwrap();
    }

    #[test]
    fn test_get_public_key_for_file() {
        let env_file = "/Users/linux_china/.dotenvx/.env.g_default";
        let public_key = get_public_key_for_file(env_file);
        println!("public key: {}", public_key.unwrap());
    }

    #[test]
    fn test_get_public_key_from_xml() {
        let file_path = "tests/demo.xml";
        let public_key = get_public_key_from_text_file(file_path).unwrap();
        println!("public key: {public_key}");
    }

    #[test]
    fn test_get_public_key_from_json() {
        let file_path = "tests/demo.json";
        let public_key = get_public_key_from_text_file(file_path).unwrap();
        println!("public key: {public_key}");
    }
}
