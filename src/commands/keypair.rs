use crate::commands::model::{DotenvxKeyStore, KeyPair};
use crate::commands::{
    EcKeyPair, KEYS_FILE_NAME, find_all_keys, get_env_file_arg, get_private_key,
    get_private_key_for_file, get_private_key_name, get_public_key_for_file, get_public_key_name,
    write_key_pair, write_private_key_to_file, write_public_key_to_file,
};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use comfy_table::Table;
use dotenvx_rs::common::get_profile_name_from_file;
use std::path::{Path, PathBuf};

pub fn keypair_command(command_matches: &ArgMatches, profile: &Option<String>) {
    // import private key
    if command_matches.get_flag("import") {
        import_private_key();
        return;
    } else if let Some(key) = command_matches.get_one::<String>("remove") {
        remove_private_key(key);
        return;
    } else if command_matches.get_flag("all") {
        list_all_pairs();
        return;
    } else if let Some(public_key) = command_matches.get_one::<String>("public-key") {
        let all_pairs = find_all_keys();
        if let Some(key_pair) = all_pairs.get(public_key) {
            println!("export DOTENV_PUBLIC_KEY={}", key_pair.public_key);
            println!("export DOTENV_PRIVATE_KEY={}", key_pair.private_key);
        } else {
            eprintln!("No key pair found for public key: {public_key}");
            std::process::exit(1);
        }
        return;
    }
    // list key pair based on public key
    let env_file = get_env_file_arg(command_matches, profile);
    let format = if let Some(arg_value) = command_matches.get_one::<String>("format") {
        arg_value.clone()
    } else {
        "json".to_owned()
    };
    let profile_name = get_profile_name_from_file(&env_file);
    let env_private_key_name = get_private_key_name(&profile_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    // read the public key declared by the env file itself, fall back to the profile's key
    let public_key = get_public_key_for_file(&env_file);
    // private key verified against the file's public key (env var, .env.keys, global store)
    let mut private_key: Option<String> = get_private_key_for_file(&env_file).ok();
    if private_key.is_none() {
        private_key = get_private_key(&profile_name).ok();
    }
    // check key pair validity
    if let Some(private_key_hex) = &private_key
        && let Ok(public_key_hex) = &public_key
    {
        let matched = EcKeyPair::from_secret_key(private_key_hex)
            .map(|kp| &kp.get_pk_hex() == public_key_hex)
            .unwrap_or(false);
        if !matched {
            eprintln!("{}", "The public key does not match the private key:".red());
            eprintln!("{env_pub_key_name}=\"{public_key_hex}\"");
            eprintln!("{env_private_key_name}=\"{private_key_hex}\"");
            std::process::exit(1);
        }
    }
    // dump the public key to .env file and private key to the .env.keys file next to it
    if command_matches.get_flag("dump") {
        let (Ok(public_key_hex), Some(private_key_hex)) = (&public_key, &private_key) else {
            eprintln!("No key pair found for {env_file}");
            std::process::exit(1);
        };
        let key_pair = KeyPair::new(public_key_hex, private_key_hex, &profile_name);
        let keys_file = keys_file_for_env_file(&env_file);
        if let Err(e) = write_public_key_to_file(&env_file, public_key_hex) {
            eprintln!("Failed to write public key to {env_file}: {e}");
            std::process::exit(1);
        }
        if let Err(e) = write_private_key_to_file(&keys_file, &env_private_key_name, &key_pair) {
            eprintln!(
                "Failed to write private key to {}: {e}",
                keys_file.display()
            );
            std::process::exit(1);
        }
        return;
    }
    if format == "shell" {
        println!(
            "export {}=\"{}\"",
            env_pub_key_name,
            public_key.unwrap_or_else(|_| "".to_owned())
        );
        println!(
            "export {}=\"{}\"",
            env_private_key_name,
            private_key.unwrap_or("".to_owned())
        );
    } else {
        let body = serde_json::json!({
            env_pub_key_name: public_key.unwrap_or_else(|_| "".to_owned()),
            env_private_key_name: private_key.unwrap_or("".to_owned()),
        });
        println!("{}", to_colored_json_auto(&body).unwrap());
    }
}

fn import_private_key() {
    let private_key = rpassword::prompt_password("Private key: ").unwrap();
    let group = rprompt::prompt_reply("Group: ").unwrap();
    let name = rprompt::prompt_reply("Name: ").unwrap();
    let profile = rprompt::prompt_reply("Profile: ").unwrap();
    if let Ok(pair) = EcKeyPair::from_input(private_key.trim()) {
        let public_key = pair.get_pk_hex();
        // store the normalized private key, not the raw input (may contain spaces or prefix)
        let mut key_pair = KeyPair::new(&public_key, &pair.get_sk_hex(), &None);
        key_pair.group = non_empty(group);
        key_pair.name = non_empty(name);
        key_pair.profile = non_empty(profile);
        write_key_pair(&key_pair).unwrap();
        println!(
            "{}",
            "✔ Private key imported successfully.".to_string().green()
        );
    } else {
        eprintln!("Invalid private key.");
        std::process::exit(1);
    }
}

fn remove_private_key(key: &str) {
    if !DotenvxKeyStore::global_path().exists() {
        eprintln!("Key store file not found");
        std::process::exit(1);
    }
    match DotenvxKeyStore::update_global(|store| {
        let removed = store.remove_private_key(key);
        Ok((removed, removed))
    }) {
        Ok(true) => println!("{}", "✔ Key removed successfully.".to_string().green()),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("Failed to remove key: {e}");
            std::process::exit(1);
        }
    }
}

fn list_all_pairs() {
    let all_pairs = find_all_keys();
    if all_pairs.is_empty() {
        println!("No key pairs found.");
        return;
    }
    let title = "All global key pairs";
    let mut table = Table::new();
    table.set_header(vec![
        "Public Key",
        "Private Key",
        "timestamp",
        "path",
        "group",
        "name",
        "profile",
        "comment",
    ]);

    for (public_key, key_pair) in &all_pairs {
        let pk_key_short: String = public_key.chars().take(6).collect();
        let sk_key_short: String = key_pair.private_key.chars().take(6).collect();
        table.add_row(vec![
            format!("{pk_key_short}..."),
            format!("{sk_key_short}..."),
            key_pair
                .timestamp
                .map(|x| x.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default(),
            key_pair.path.clone().unwrap_or_default(),
            key_pair.group.clone().unwrap_or_default(),
            key_pair.name.clone().unwrap_or_default(),
            key_pair.profile.clone().unwrap_or_default(),
            key_pair.comment.clone().unwrap_or_default(),
        ]);
    }
    println!("{title}");
    println!("{table}");
}

/// `.env.keys` in the same directory as `env_file`.
fn keys_file_for_env_file(env_file: &str) -> PathBuf {
    match Path::new(env_file).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(KEYS_FILE_NAME),
        _ => PathBuf::from(KEYS_FILE_NAME),
    }
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_file_for_env_file() {
        assert_eq!(
            keys_file_for_env_file(".env"),
            PathBuf::from(KEYS_FILE_NAME)
        );
        assert_eq!(
            keys_file_for_env_file("config/.env.prod"),
            Path::new("config").join(KEYS_FILE_NAME)
        );
    }

    #[test]
    fn test_non_empty() {
        assert_eq!(non_empty("  ".to_owned()), None);
        assert_eq!(non_empty(" dev ".to_owned()), Some("dev".to_owned()));
    }

    #[test]
    fn test_from_secret_key_invalid_does_not_panic() {
        assert!(EcKeyPair::from_secret_key("not-a-hex-key").is_err());
        assert!(EcKeyPair::from_secret_key("00").is_err());
        let kp = EcKeyPair::generate();
        let parsed = EcKeyPair::from_secret_key(&format!(" {} ", kp.get_sk_hex())).unwrap();
        assert_eq!(parsed.get_pk_hex(), kp.get_pk_hex());
    }
}
