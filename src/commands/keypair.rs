use crate::commands::model::KeyPair;
use crate::commands::{
    find_all_keys, find_private_key_from_home, get_env_file_arg, get_private_key, get_private_key_name,
    get_public_key, get_public_key_name, write_key_pair, write_private_key_to_file, write_public_key_to_file,
    EcKeyPair, KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored::Colorize;
use colored_json::to_colored_json_auto;
use dotenvx_rs::common::get_profile_name_from_file;
use prettytable::format::Alignment;
use prettytable::{row, Cell, Row, Table};

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
    let public_key = get_public_key(&profile_name);
    let mut private_key: Option<String> = None;
    if let Ok(public_key_hex) = &public_key {
        private_key = find_private_key_from_home(public_key_hex);
    }
    if private_key.is_none() {
        private_key = get_private_key(&profile_name).ok();
    }
    // check key pair validity
    if let Some(private_key_hex) = &private_key
        && let Ok(public_key_hex) = &public_key
    {
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
    if let Ok(pair) = EcKeyPair::from_input(&private_key) {
        let public_key = pair.get_pk_hex();
        let mut key_pair = KeyPair::new(&public_key, &private_key, &None);
        key_pair.group = Some(group);
        key_pair.name = Some(name);
        key_pair.profile = Some(profile);
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
        Cell::new_align(title, Alignment::CENTER).with_hspan(8),
    ]));
    table.add_row(row![
        "Public Key",
        "Private Key",
        "timestamp",
        "path",
        "group",
        "name",
        "profile",
        "comment"
    ]);

    for (public_key, key_pair) in &all_pairs {
        let pk_key_short = public_key[0..6].to_string();
        let sk_key_short = key_pair.private_key[0..6].to_string();
        table.add_row(row![
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
    table.printstd();
}
