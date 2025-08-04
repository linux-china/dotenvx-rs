use crate::commands::framework::detect_framework;
use crate::commands::{
    create_env_file, get_env_file_arg, get_private_key_name_for_file, is_public_key_included, write_private_key_to_file,
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
        create_global_env_keys();
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
    let framework_arg: Option<String> = command_matches.get_one("framework").map(|x| x.to_string());
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let pair = format!("{}={}", "KEY1", "value1");
    // detect framework
    if let Some(framework) = framework_arg.or_else(|| detect_framework())
        && framework == "gofr"
        && env_file.starts_with(".env")
    {
        env_file = format!("configs/{env_file}");
    }
    create_env_file(&env_file, &public_key, Some(&pair));
    // create private key file
    let private_key_name = get_private_key_name_for_file(&env_file);
    write_private_key_to_file(KEYS_FILE_NAME, &private_key_name, &kp.get_sk_hex()).unwrap();
    println!(
        "{}",
        format!("✔ Succeed, please check .env file({env_file}) and .env.keys files.").green()
    );
}

fn generate_kp_and_export() {
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let private_key = kp.get_sk_hex();
    println!("export DOTENV_PUBLIC_KEY={public_key}");
    println!("export DOTENV_PRIVATE_KEY={private_key}");
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
            lines.push(format!("DOTENV_PRIVATE_KEY={private_key}"));
        }
        // private keys for each profile
        for profile in profiles {
            let kp = EcKeyPair::generate();
            let private_key = kp.get_sk_hex();
            lines.push(format!(
                "DOTENV_PRIVATE_KEY_{}={}",
                profile.to_uppercase(),
                private_key
            ));
        }
        let private_keys = lines.join("\n");
        let keys_file_id = uuid::Uuid::now_v7().to_string();
        let file_content = format!(
            r#"
# ---
# uuid: {keys_file_id}
# name: project_name
# group: group_name
# ---

{private_keys}
"#
        );
        fs::write(&keys_file_path, file_content.trim_start().as_bytes()).unwrap();
        println!(
            "{}",
            "Global $HOME/.env.keys file created with profiles dev, test, perf, sand, stage, prod."
                .green()
        );
    }
}
