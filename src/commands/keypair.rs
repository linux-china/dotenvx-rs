use crate::commands::model::KeyPair;
use crate::commands::{
    find_all_keys, find_dotenv_keys_file, get_env_file_arg, get_private_key, get_private_key_name,
    get_public_key, get_public_key_name, write_key_pair, write_private_key_to_file, write_public_key_to_file,
    EcKeyPair, KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use dotenvx_rs::common::get_profile_name_from_file;
use prettytable::format::Alignment;
use prettytable::{row, Cell, Row, Table};
use std::env;

pub fn keypair_command(command_matches: &ArgMatches, profile: &Option<String>) {
    // import private key
    if command_matches.get_flag("import") {
        import_private_key();
        return;
    } else if command_matches.get_flag("all") {
        list_all_pairs();
        return;
    }
    let env_file = get_env_file_arg(command_matches, profile);
    let format = if let Some(arg_value) = command_matches.get_one::<String>("format") {
        arg_value.clone()
    } else {
        "json".to_owned()
    };
    let profile_name = get_profile_name_from_file(&env_file);
    let env_private_key_name = get_private_key_name(&profile_name);
    let env_pub_key_name = get_public_key_name(&profile_name);
    let keys_file_path = find_dotenv_keys_file();
    if env::var(&env_private_key_name).is_err() && keys_file_path.is_none() {
        if format == "shell" {
            println!("{env_pub_key_name}=\n{env_private_key_name}=");
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
                eprintln!("{env_pub_key_name}={public_key_hex}");
                eprintln!("{env_private_key_name}={private_key_hex}");
                std::process::exit(1);
            }
        }
        // dump the public key to .env file and private key to .env.keys file
        if command_matches.get_flag("dump") {
            let public_key_hex = public_key.unwrap().to_string();
            let key_pair = KeyPair::new(&public_key_hex, &private_key.unwrap(), profile);
            write_public_key_to_file(&env_file, &public_key_hex).unwrap();
            write_private_key_to_file(KEYS_FILE_NAME, &env_private_key_name, &key_pair).unwrap();
            return;
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

fn import_private_key() {
    let private_key = rpassword::prompt_password("Private Key: ").unwrap();
    if let Ok(pair) = EcKeyPair::from_input(&private_key) {
        let public_key = pair.get_pk_hex();
        let key_pair = KeyPair::new(&public_key, &private_key, &None);
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

fn list_all_pairs() {
    let all_pairs = find_all_keys();
    if all_pairs.is_empty() {
        println!("No key pairs found.");
        return;
    }
    let title = "All global key pairs";
    let mut table = Table::new();
    table.set_titles(Row::new(vec![
        Cell::new_align(title, Alignment::CENTER).with_hspan(5),
    ]));
    table.add_row(row![
        "Public Key",
        "Private Key",
        "group",
        "name",
        "profile",
    ]);

    for (public_key, key_pair) in &all_pairs {
        let pk_key_short = public_key[0..16].to_string();
        let sk_key_short = key_pair.private_key[0..10].to_string();
        table.add_row(row![
            format!("{pk_key_short}..."),
            format!("{sk_key_short}..."),
            key_pair.group.clone().unwrap_or_default(),
            key_pair.name.clone().unwrap_or_default(),
            key_pair.profile.clone().unwrap_or_default(),
        ]);
    }
    table.printstd();
}
