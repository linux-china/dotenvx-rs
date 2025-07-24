use crate::commands::{
    create_env_file, get_env_file_arg, get_private_key_name_for_file, write_private_key_to_file, EcKeyPair,
    KEYS_FILE_NAME,
};
use clap::ArgMatches;
use colored::Colorize;
use std::path::Path;

pub fn init_command(command_matches: &ArgMatches) {
    if command_matches.get_flag("stdout") {
        generate_kp_and_print();
        return;
    }
    let env_file = get_env_file_arg(command_matches);
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

fn generate_kp_and_print() {
    let kp = EcKeyPair::generate();
    let public_key = kp.get_pk_hex();
    let private_key = kp.get_sk_hex();
    println!("{}:  {}", "Public Key".green(), public_key);
    println!("{}: {}", "Private Key".red(), private_key);
}
