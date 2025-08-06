use crate::commands::framework::detect_framework;
use crate::commands::model::KeyPair;
use crate::commands::{
    create_env_file, get_env_file_arg, is_public_key_included, write_key_pair, write_key_pairs,
    EcKeyPair, KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored::Colorize;
use std::fs;
use std::path::Path;

pub fn init_command(command_matches: &ArgMatches, profile: &Option<String>) {
    if command_matches.get_flag("stdout") {
        generate_kp_and_export();
        return;
    }
    if command_matches.get_flag("global") {
        create_global_env_keys(profile);
        return;
    }
    let mut env_file = get_env_file_arg(command_matches, profile);
    let env_file_exists = Path::new(&env_file).exists();
    if env_file_exists {
        if let Ok(file_content) = fs::read_to_string(&env_file) {
            if is_public_key_included(&file_content) {
                eprintln!("The .env file already exists and contains a public key: {env_file}");
                return;
            }
        }
    }
    let group_arg = command_matches.get_one::<String>("group").cloned();
    let name_arg = command_matches.get_one::<String>("name").cloned();
    let framework_arg = command_matches.get_one::<String>("framework").cloned();
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let mut pair = format!("{}={}", "KEY1", "value1");
    // detect framework
    if let Some(framework) = framework_arg.or_else(detect_framework) {
        if framework == "gofr" && env_file.starts_with(".env") {
            env_file = format!("configs/{env_file}");
        } else if framework == "spring-boot" {
            pair = format!("{}={}", "key1", "value1");
        }
    }
    create_env_file(&env_file, &public_key, Some(&pair), &group_arg, &name_arg);
    // create private key file
    let key_pair = KeyPair::from(
        &public_key,
        &kp.get_sk_hex(),
        &group_arg,
        &name_arg,
        profile,
    );
    // write to global .env.keys.json file, no local .env.key file generated
    write_key_pair(&key_pair).unwrap();
    //let private_key_name = get_private_key_name_for_file(&env_file);
    //write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &key_pair).unwrap();
    println!(
        "{}",
        format!("✔ Succeed, please check .env file({env_file}).").green()
    );
}

fn generate_kp_and_export() {
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let private_key = kp.get_sk_hex();
    println!("export DOTENV_PUBLIC_KEY={public_key}");
    println!("export DOTENV_PRIVATE_KEY={private_key}");
}

fn create_global_env_keys(profile: &Option<String>) {
    let keys_file_path = dirs::home_dir().unwrap().join(KEYS_FILE_NAME);
    if keys_file_path.exists() {
        let file_content = fs::read_to_string(&keys_file_path).unwrap();
        let private_key_name = if let Some(profile_name) = profile {
            format!("DOTENV_PRIVATE_KEY_{}", profile_name.to_uppercase())
        } else {
            "DOTENV_PRIVATE_KEY".to_string()
        };
        if file_content.contains(&format!("{private_key_name}=")) {
            eprintln!("{} already exists.", private_key_name.red());
        } else {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            let new_line = format!("{private_key_name}={private_key}");
            let new_file_content = format!("{}\n{}\n", file_content.trim_end(), new_line);
            fs::write(&keys_file_path, new_file_content.as_bytes()).unwrap();
            let key_pair = KeyPair::new(&kp.get_pk_hex(), &private_key, profile);
            write_key_pair(&key_pair).unwrap();
            eprintln!(
                "{}",
                format!("{private_key_name} added to $HOME/.env.keys").green()
            );
        }
    } else {
        let profiles = vec!["dev", "test", "perf", "sandbox", "stage", "prod"];
        let mut lines: Vec<String> = Vec::new();
        // global private key
        {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            lines.push(format!("DOTENV_PRIVATE_KEY={private_key}"));
        }
        let mut key_pairs: Vec<KeyPair> = Vec::new();
        // private keys for each profile
        for profile in profiles {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            lines.push(format!(
                "DOTENV_PRIVATE_KEY_{}={}",
                profile.to_uppercase(),
                private_key
            ));
            let key_pair = KeyPair::new(&kp.get_pk_hex(), &private_key, &Some(profile.to_string()));
            key_pairs.push(key_pair);
        }
        // dotenvx cloud key pair
        let dotenvx_cloud_keypair = EcKeyPair::generate();
        let key_pair = KeyPair::from(
            &dotenvx_cloud_keypair.get_pk_hex(),
            &dotenvx_cloud_keypair.get_sk_hex(),
            &Some("dotenvx".to_owned()),
            &Some("dotenvx-cloud".to_owned()),
            &Some("g_dotenvx".to_owned()),
        );
        key_pairs.push(key_pair);
        let private_keys = lines.join("\n");
        let keys_file_id = uuid::Uuid::now_v7().to_string();
        let file_content = format!(
            r#"
# ---
# uuid: {keys_file_id}
# ---

{private_keys}
"#
        );
        fs::write(&keys_file_path, file_content.trim_start().as_bytes()).unwrap();
        // write key pairs to global .env.keys.json file
        write_key_pairs(&key_pairs).unwrap();
        println!(
            "{}",
            "Global $HOME/.env.keys file created with profiles dev, test, perf, sand, stage, prod."
                .green()
        );
    }
}
