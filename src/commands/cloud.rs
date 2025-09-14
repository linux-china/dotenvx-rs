use crate::commands::dotenvx_cloud;
use crate::commands::dotenvx_cloud::find_dotenvx_cloud_key_pair;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};

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
    // Placeholder for signup command logic
    println!("Signing up... (this feature is not implemented yet)");
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
        println!("No dotenvx-cloud key pair found. Please sign up first.");
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
