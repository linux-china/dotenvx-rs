use crate::commands::{
    get_env_file_arg, get_private_key, get_private_key_name, get_public_key, get_public_key_name,
    EcKeyPair, KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use dotenvx_rs::common::get_profile_name_from_file;
use std::env;
use std::path::Path;

pub fn keypair_command(command_matches: &ArgMatches, profile: &Option<String>) {
    let env_file = get_env_file_arg(command_matches, profile);
    let format = if let Some(arg_value) = command_matches.get_one::<String>("format") {
        arg_value.clone()
    } else {
        "json".to_owned()
    };
    let profile_name = get_profile_name_from_file(&env_file);
    let env_private_key_name = get_private_key_name(&profile_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    if env::var(&env_private_key_name).is_err() && !Path::new(KEYS_FILE_NAME).exists() {
        if format == "shell" {
            println!("{}=\n{}=", env_pub_key_name, env_private_key_name);
        } else {
            let body = serde_json::json!({
                env_pub_key_name: "".to_string(),
                env_private_key_name: "".to_string(),
            });
            println!("{}", to_colored_json_auto(&body).unwrap());
        }
    } else {
        let private_key = get_private_key(&profile_name);
        let public_key = get_public_key(&profile_name);
        // check key pair validity
        if private_key.is_ok() && public_key.is_ok() {
            let public_key_hex = public_key.as_ref().unwrap();
            let private_key_hex = private_key.as_ref().unwrap();
            let kp = EcKeyPair::from_secret_key(private_key_hex);
            let reversed_pk_hex = kp.get_pk_hex();
            if &reversed_pk_hex != public_key_hex {
                eprintln!("{}", "The public key does not match the private key:".red());
                eprintln!("{}={}", env_pub_key_name, public_key_hex);
                eprintln!("{}={}", env_private_key_name, private_key_hex);
                std::process::exit(1);
            }
        }
        if format == "shell" {
            println!(
                "export {}={}",
                env_pub_key_name,
                public_key.unwrap_or_else(|_| "".to_owned())
            );
            println!(
                "export {}={}",
                env_private_key_name,
                private_key.unwrap_or_else(|_| "".to_owned())
            );
        } else {
            let body = serde_json::json!({
                env_pub_key_name: public_key.unwrap_or_else(|_| "".to_owned()),
                env_private_key_name: private_key.unwrap_or_else(|_| "".to_owned()),
            });
            println!("{}", to_colored_json_auto(&body).unwrap());
        }
    }
}
