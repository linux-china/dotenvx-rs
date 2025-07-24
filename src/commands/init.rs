use crate::commands::{
    create_env_file, get_env_file_arg, get_private_key_name_for_file, write_private_key_to_file, EcKeyPair,
    KEYS_FILE_NAME,
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
        create_global_env_keys();
        return;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    let env_file_exists = Path::new(&env_file).exists();
    if env_file_exists {
        eprintln!("The .env file already exists: {}", env_file);
        return;
    }
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let pair = format!("{}={}", "KEY1", "value1");
    create_env_file(&env_file, &public_key, Some(&pair));
    println!(
        "{}",
        format!("Initialized new .env file with name: {}", env_file).green()
    );
    let private_key_name = get_private_key_name_for_file(&env_file);
    write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &kp.get_sk_hex()).unwrap();
}

fn generate_kp_and_export() {
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let private_key = kp.get_sk_hex();
    println!("export DOTENV_PUBLIC_KEY={}", public_key);
    println!("export DOTENV_PRIVATE_KEY={}", private_key);
}

fn create_global_env_keys() {
    let keys_file_path = dirs::home_dir().unwrap().join(KEYS_FILE_NAME);
    if keys_file_path.exists() {
        eprintln!(
            "{}",
            "The global keys file already exists: $HOME/.env.keys".red()
        );
    } else {
        let profiles = vec!["dev", "test", "perf", "sandbox", "stage", "prod"];
        let mut lines: Vec<String> = Vec::new();
        // global private key
        {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            lines.push(format!("DOTENV_PRIVATE_KEY=\"{}\"", private_key));
        }
        // private keys for each profile
        for profile in profiles {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            lines.push(format!(
                "DOTENV_PRIVATE_KEY_{}=\"{}\"",
                profile.to_uppercase(),
                private_key
            ));
        }
        let private_keys = lines.join("\n");
        let file_content = format!(
            r#"
#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/

{}
"#,
            private_keys
        );
        fs::write(&keys_file_path, file_content.trim_start().as_bytes()).unwrap();
        println!(
            "{}",
            "Global $HOME/.env.keys file created with profiles dev, test, perf, sand, stage, prod."
                .green()
        );
    }
}
