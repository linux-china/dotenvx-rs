use crate::clap_app::build_dotenvx_app;
use crate::commands::decrypt::decrypt_command;
use crate::commands::encrypt::encrypt_command;
use crate::commands::get_cmd::get_command;
use crate::commands::init::init_command;
use crate::commands::keypair::keypair_command;
use crate::commands::list::ls_command;
use crate::commands::rotate::rotate_command;
use crate::commands::run::run_command;
use crate::commands::set_cmd::set_command;
use std::env;

mod clap_app;
pub mod commands;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = build_dotenvx_app();
    let raw_args: Vec<String> = env::args().collect();
    let sub_command_index = raw_args.iter().position(|arg| arg == "--").unwrap_or(0);
    if sub_command_index > 0 && raw_args[1] == "run" {
        let dotenvx_args = raw_args[0..sub_command_index]
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>();
        let matches = app.try_get_matches_from(dotenvx_args).unwrap();
        let command_matches = matches.subcommand_matches("run").unwrap();
        let exit_code = run_command(&raw_args[sub_command_index + 1..], command_matches);
        std::process::exit(exit_code);
    }
    let matches = app.get_matches();
    if let Some((command, command_matches)) = matches.subcommand() {
        match command {
            "init" => init_command(command_matches),
            "encrypt" => encrypt_command(command_matches),
            "decrypt" => decrypt_command(command_matches),
            "keypair" => keypair_command(command_matches),
            "ls" => ls_command(command_matches),
            "get" => get_command(command_matches),
            "set" => set_command(command_matches),
            "rotate" => rotate_command(command_matches),
            &_ => println!("Unknown command"),
        }
    }
    Ok(())
}
