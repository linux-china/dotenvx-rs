use crate::commands::crypt_util::{encrypt_env_item, EcKeyPair};
use crate::commands::dotenvx_cloud::find_dotenvx_cloud_key_pair;
use crate::commands::model::KeyPair;
use crate::commands::{
    create_env_file, crypt_util, dotenvx_cloud, get_dotenvx_home, write_key_pair,
};
use clap::ArgMatches;

pub fn cloud_command(command_matches: &ArgMatches) {
    if let Some((command, sub_command_matches)) = command_matches.subcommand() {
        match command {
            "signup" => {
                signup_command(sub_command_matches);
            }
            "me" => {
                me_command(sub_command_matches);
            }
            "send" => {
                send_command(sub_command_matches);
            }
            "sync" => {
                sync_command(sub_command_matches);
            }
            "backup" => {
                backup_command(sub_command_matches);
            }
            &_ => println!("Unknown command"),
        }
    }
}

pub fn signup_command(command_matches: &ArgMatches) {
    let nick = rprompt::prompt_reply("Nick: ").unwrap();
    let email = rprompt::prompt_reply("Email: ").unwrap();
    let phone = rprompt::prompt_reply("Phone: ").unwrap();
    if nick.is_empty() || email.is_empty() || phone.is_empty() {
        eprintln!("Nick, email and phone are required.");
        std::process::exit(1);
    }
    let key_pair = if let Some(pair) = find_dotenvx_cloud_key_pair() {
        pair
    } else {
        let dotenvx_cloud_keypair = EcKeyPair::generate();
        let key_pair = KeyPair::from(
            &dotenvx_cloud_keypair.get_pk_hex(),
            &dotenvx_cloud_keypair.get_sk_hex(),
            &Some("dotenvx".to_owned()),
            &Some("dotenvx-cloud".to_owned()),
            &Some("g_dotenvx".to_owned()),
        );
        write_key_pair(&key_pair).unwrap();
        key_pair
    };
    let private_key_bytes = hex::decode(&key_pair.private_key).unwrap();
    let private_key_sha256 = crypt_util::sha256(&private_key_bytes);
    if let Ok(result) = dotenvx_cloud::register(
        &key_pair.public_key,
        &private_key_sha256,
        &nick,
        &email,
        &phone,
    ) {
        println!("Registration successful!");
        let env_file = get_dotenvx_home().join(".env.g_dotenvx");
        let pairs = format!(
            "{}={}\n{}={}\n{}={}\n{}={}\n",
            "NICK",
            nick,
            "EMAIL",
            email,
            "PASSWORD",
            encrypt_env_item(&key_pair.public_key, &result.password).unwrap(),
            "TOTP_URL",
            encrypt_env_item(&key_pair.public_key, &result.totp_url).unwrap(),
        );
        create_env_file(
            env_file,
            &key_pair.public_key,
            Some(&pairs),
            &Some("dotenvx".to_owned()),
            &Some("dotenvx-cli".to_owned()),
        )
    } else {
        eprintln!("Registration failed.");
    }
}

pub fn me_command(command_matches: &ArgMatches) {
    if let Some(pair) = find_dotenvx_cloud_key_pair() {
        if let Ok(self_info) = dotenvx_cloud::fetch_self_info(&pair.private_key) {
            println!("id: {}", self_info.id);
            println!("nick: {}", self_info.nick);
            if let Some(email) = self_info.email {
                println!("email: {email}");
            }
            if let Some(phone) = self_info.phone {
                println!("phone: {phone}");
            }
        }
    } else {
        println!("No Dotenvx Cloud key pair found. Please sign up first.");
    }
}

pub fn send_command(command_matches: &ArgMatches) {
    // Placeholder for send command logic
    println!("Sending data... (this feature is not implemented yet)");
}

pub fn sync_command(command_matches: &ArgMatches) {
    // Placeholder for sync command logic
    println!("Syncing data... (this feature is not implemented yet)");
}

pub fn backup_command(command_matches: &ArgMatches) {
    // Placeholder for backup command logic
    println!("Backing up data... (this feature is not implemented yet)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_fetch_self_info() {}
}
