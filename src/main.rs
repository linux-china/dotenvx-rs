use crate::clap_app::build_dotenvx_app;
use crate::commands::cloud::cloud_command;
use crate::commands::completion::completion_command;
use crate::commands::crypt_util::{
    decrypt_file_to_bytes, encrypt_bytes_to_file, encrypt_file, write_file_atomic,
};
use crate::commands::decrypt::decrypt_command;
use crate::commands::del_cmd::del_command;
use crate::commands::diff::diff_command;
use crate::commands::doctor::doctor_command;
use crate::commands::encrypt::encrypt_command;
use crate::commands::get_cmd::get_command;
use crate::commands::init::init_command;
use crate::commands::keypair::keypair_command;
use crate::commands::link::link_command;
use crate::commands::linter::linter_command;
use crate::commands::list::ls_command;
use crate::commands::rotate::rotate_command;
use crate::commands::run::{run_command, run_command_line};
use crate::commands::set_cmd::set_command;
use crate::commands::sync::sync_command;
use crate::commands::verify::verify_command;
use crate::commands::{get_dotenvx_home, merge_env_keys_text, merge_sealed_key_store};
use crate::shims::{is_shim_command, run_shim};
use clap::ArgMatches;
use dotenvx_rs::common::get_profile_name_from_env;
use std::env;
use std::ffi::OsString;

mod clap_app;
pub mod commands;
pub mod shims;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = build_dotenvx_app();
    let mut raw_args: Vec<OsString> = env::args_os().collect();
    // get the command name
    let mut command_name = raw_args[0].clone().to_str().unwrap().to_owned();
    if command_name.contains('/') || command_name.contains('\\') {
        if let Some(pos) = command_name.rfind(['/', '\\']) {
            command_name = command_name[pos + 1..].to_string();
        }
    }
    // check if the command is a shim command
    if is_shim_command(command_name.as_str()) {
        let command_args = raw_args[1..]
            .iter()
            .map(|s| s.to_str().unwrap().to_string())
            .collect::<Vec<String>>();
        let exist_code = run_shim(&command_name, &command_args);
        std::process::exit(exist_code);
    }
    let delegate_command_index = raw_args.iter().position(|arg| arg == "--").unwrap_or(0);
    // check if the run sub-command is present
    if delegate_command_index > 0 {
        let dotenvx_args = raw_args[0..delegate_command_index]
            .iter()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<&str>>();
        if dotenvx_args.contains(&"run") {
            let matches = app.try_get_matches_from(dotenvx_args).unwrap();
            let command_matches = matches.subcommand_matches("run").unwrap();
            let profile = get_profile(&matches);
            let command_args = raw_args[delegate_command_index + 1..]
                .iter()
                .map(|s| s.to_str().unwrap().to_string())
                .collect::<Vec<String>>();
            let exit_code = run_command(&command_args, command_matches, &profile);
            std::process::exit(exit_code);
        }
    }
    // check "-pp" for decryption to be compatible with python-dotenvx
    normalize_pretty_print_arg(&mut raw_args);
    let matches = app.get_matches_from(raw_args);
    // check no-color flag
    if matches.get_flag("no-color") {
        unsafe {
            env::set_var("NO_COLOR", "1");
        }
    }
    // seal/unseal $HOME/.env.keys file
    if matches.get_flag("seal") {
        encrypt_env_keys_file();
        return Ok(());
    } else if matches.get_flag("unseal") {
        decrypt_env_keys_file();
        return Ok(());
    }
    // check if the --profile flag is set
    let profile = get_profile(&matches);
    // check -c and run the command
    if matches.get_one::<String>("command").is_some() {
        let exit_code = run_command_line(&matches, &profile);
        std::process::exit(exit_code);
    }
    // run the sub-commands
    if let Some((command, command_matches)) = matches.subcommand() {
        match command {
            "init" => init_command(command_matches, &profile),
            "encrypt" => encrypt_command(command_matches, &profile),
            "decrypt" => decrypt_command(command_matches, &profile),
            "verify" => verify_command(command_matches, &profile),
            "keypair" | "kp" => keypair_command(command_matches, &profile),
            "ls" => ls_command(command_matches, &profile),
            "link" => link_command(command_matches, &command_name),
            "get" => get_command(command_matches, &profile),
            "set" => set_command(command_matches, &profile),
            "del" => del_command(command_matches, &profile),
            "sync" => sync_command(command_matches),
            "diff" => diff_command(command_matches),
            "rotate" => rotate_command(command_matches, &profile),
            "lint" => linter_command(command_matches),
            "doctor" => doctor_command(command_matches),
            "cloud" => cloud_command(command_matches),
            "completion" => completion_command(command_matches),
            &_ => println!("Unknown command"),
        }
    }
    Ok(())
}

/// Rewrite python-dotenvx style `-pp` into `--pretty-print`.
///
/// Only the `get` sub-command has `--pretty-print`, so `-pp` is rewritten only when it
/// appears as a flag of `get`: before any `--` and not as the value of an option such as
/// `--format`. Values of other sub-commands (for example `set KEY -pp`) are left untouched.
fn normalize_pretty_print_arg(raw_args: &mut [OsString]) {
    // locate the sub-command, skipping global options and their values
    let mut index = 1;
    let mut sub_command_index = None;
    while index < raw_args.len() {
        let Some(arg) = raw_args[index].to_str() else {
            return;
        };
        match arg {
            "--" => return,
            // `-c/--command` consumes the rest of the arguments, so there is no sub-command
            "-c" | "--command" => return,
            "-p" | "--profile" => index += 2,
            _ if arg.starts_with('-') => index += 1,
            _ => {
                sub_command_index = Some(index);
                break;
            }
        }
    }
    let Some(sub_command_index) = sub_command_index else {
        return;
    };
    if raw_args[sub_command_index] != "get" {
        return;
    }
    let mut index = sub_command_index + 1;
    while index < raw_args.len() {
        let Some(arg) = raw_args[index].to_str() else {
            index += 1;
            continue;
        };
        match arg {
            "--" => return,
            "-f" | "--env-file" | "--format" => index += 2,
            "-pp" => {
                raw_args[index] = "--pretty-print".into();
                index += 1;
            }
            _ => index += 1,
        }
    }
}

fn encrypt_env_keys_file() {
    let password = rpassword::prompt_password("Your password: ").unwrap();
    if password.trim().is_empty() {
        eprintln!("Password must not be empty. Nothing changed.");
        return;
    }
    let password_confirm = rpassword::prompt_password("Password again: ").unwrap();
    if password != password_confirm {
        eprintln!("Passwords do not match. Please try again.");
        return;
    }
    let home_dir = dirs::home_dir().unwrap();
    // encrypt the $HOME/.env.keys file to $HOME/.env.keys.aes
    let keys_file_path = home_dir.join(".env.keys");
    if keys_file_path.exists() {
        let encrypted_file_path = home_dir.join(".env.keys.aes");
        if let Err(e) = seal_env_keys(&keys_file_path, &encrypted_file_path, &password) {
            eprintln!("Failed to encrypt the $HOME/.env.keys file: {e}. Nothing changed.");
            return;
        }
        println!("✔ Successfully encrypted the $HOME/.env.keys file to .env.keys.aes");
    }
    // encrypt the $DOTENVX_DIR/.env.keys.json, default $HOME/.dotenvx/.env.keys.json
    let dotenvx_home = get_dotenvx_home();
    let keys_file_path = dotenvx_home.join(".env.keys.json");
    if keys_file_path.exists() {
        let encrypted_file_path = dotenvx_home.join(".env.keys.json.aes");
        // a previous sealed key store exists: merge its keys first, otherwise they would be lost
        if encrypted_file_path.exists() {
            if let Err(e) = merge_sealed_key_store(&encrypted_file_path, &password) {
                eprintln!(
                    "Failed to merge the existing {} file: {e}. Nothing changed.",
                    encrypted_file_path.display()
                );
                return;
            }
        }
        // encrypt_file writes a temp file, fsyncs and verifies it before replacing the .aes file,
        // so the plaintext is only removed once a readable sealed copy is on disk
        match encrypt_file(&keys_file_path, &encrypted_file_path, &password)
            .and_then(|_| Ok(std::fs::remove_file(&keys_file_path)?))
        {
            Ok(_) => println!(
                "✔ Successfully encrypted the {} file to .env.keys.json.aes",
                keys_file_path.display()
            ),
            Err(e) => eprintln!(
                "Failed to encrypt the {} file: {e}. Please check your password and try again.",
                keys_file_path.display()
            ),
        }
    }
}

/// Seal `$HOME/.env.keys` into `$HOME/.env.keys.aes`, merging the keys of an existing
/// `.env.keys.aes` first so they are not lost. The plaintext is removed only after the
/// new sealed file has been written, fsynced and verified.
fn seal_env_keys(
    keys_file_path: &std::path::Path,
    encrypted_file_path: &std::path::Path,
    password: &str,
) -> anyhow::Result<()> {
    let mut plain_text = std::fs::read_to_string(keys_file_path)?;
    if encrypted_file_path.exists() {
        let sealed_bytes = decrypt_file_to_bytes(encrypted_file_path, password).map_err(|e| {
            anyhow::anyhow!(
                "cannot decrypt the existing {} with this password ({e})",
                encrypted_file_path.display()
            )
        })?;
        let (merged, conflicts) =
            merge_env_keys_text(&plain_text, &String::from_utf8(sealed_bytes)?);
        warn_env_keys_conflicts(&conflicts);
        plain_text = merged;
    }
    encrypt_bytes_to_file(plain_text.as_bytes(), encrypted_file_path, password)?;
    std::fs::remove_file(keys_file_path)?;
    Ok(())
}

fn warn_env_keys_conflicts(conflicts: &[String]) {
    for key in conflicts {
        eprintln!(
            "Warning: {key} has different values in $HOME/.env.keys and $HOME/.env.keys.aes, keeping the one in $HOME/.env.keys"
        );
    }
}

fn decrypt_env_keys_file() {
    let password = rpassword::prompt_password("Your password: ").unwrap();
    if password.is_empty() {
        eprintln!("Password must not be empty.");
        return;
    }
    let home_dir = dirs::home_dir().unwrap();
    let encrypted_file_path = home_dir.join(".env.keys.aes");
    if encrypted_file_path.exists() {
        let keys_file_path = home_dir.join(".env.keys");
        match unseal_env_keys(&encrypted_file_path, &keys_file_path, &password) {
            Ok(_) => println!("✔ Successfully decrypted the .env.keys.aes file to $HOME/.env.keys"),
            Err(e) => eprintln!(
                "Failed to decrypt the $HOME/.env.keys.aes file: {e}. Please check your password and try again."
            ),
        }
    }
    let encrypted_file_path = get_dotenvx_home().join(".env.keys.json.aes");
    if encrypted_file_path.exists() {
        // merge into the existing .env.keys.json (if any) instead of overwriting it
        match merge_sealed_key_store(&encrypted_file_path, &password) {
            Ok(_) => println!(
                "✔ Successfully decrypted the {} file to .env.keys.json",
                encrypted_file_path.display()
            ),
            Err(e) => eprintln!(
                "Failed to decrypt the {} file: {e}. Please check your password and try again.",
                encrypted_file_path.display()
            ),
        }
    }
}

/// Restore `$HOME/.env.keys` from `$HOME/.env.keys.aes`. When `$HOME/.env.keys` already exists
/// (created after `--seal`), the sealed keys are merged into it instead of overwriting it.
fn unseal_env_keys(
    encrypted_file_path: &std::path::Path,
    keys_file_path: &std::path::Path,
    password: &str,
) -> anyhow::Result<()> {
    let sealed_text = String::from_utf8(decrypt_file_to_bytes(encrypted_file_path, password)?)?;
    let plain_text = if keys_file_path.exists() {
        let current_text = std::fs::read_to_string(keys_file_path)?;
        let (merged, conflicts) = merge_env_keys_text(&current_text, &sealed_text);
        warn_env_keys_conflicts(&conflicts);
        merged
    } else {
        sealed_text
    };
    write_file_atomic(keys_file_path, plain_text.as_bytes())
}

fn get_profile(global_matches: &ArgMatches) -> Option<String> {
    let profile = global_matches
        .get_one::<String>("profile")
        .map(|s| s.to_owned());
    // If profile is not set, try to read from environment variables
    if profile.is_none() {
        return get_profile_name_from_env();
    }
    profile
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    #[test]
    fn test_seal_unseal_env_keys_merges() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("dotenvx-seal-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let keys = dir.join(".env.keys");
        let aes = dir.join(".env.keys.aes");
        let password = "test-password";

        // first seal: plaintext is removed, no temp file left behind
        std::fs::write(&keys, "DOTENV_PRIVATE_KEY=\"k1\"\n")?;
        seal_env_keys(&keys, &aes, password)?;
        assert!(!keys.exists());
        assert!(!dir.join(".env.keys.aes.tmp").exists());

        // a new .env.keys created after seal: sealing again keeps the old sealed keys
        std::fs::write(&keys, "DOTENV_PRIVATE_KEY_PROD=\"k2\"\n")?;
        seal_env_keys(&keys, &aes, password)?;
        // wrong password: nothing changes
        std::fs::write(&keys, "DOTENV_PRIVATE_KEY_TEST=\"k3\"\n")?;
        assert!(seal_env_keys(&keys, &aes, "wrong").is_err());
        assert!(keys.exists());

        // unseal merges into the existing .env.keys instead of overwriting it
        unseal_env_keys(&aes, &keys, password)?;
        let text = std::fs::read_to_string(&keys)?;
        for expected in ["k1", "k2", "k3"] {
            assert!(text.contains(expected), "{expected} missing in {text}");
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(args: &[&str]) -> Vec<String> {
        let mut raw_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        normalize_pretty_print_arg(&mut raw_args);
        raw_args
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect()
    }

    #[test]
    fn test_pp_rewritten_for_get() {
        assert_eq!(
            normalize(&["dotenvx", "get", "-pp"]),
            ["dotenvx", "get", "--pretty-print"]
        );
        assert_eq!(
            normalize(&["dotenvx", "--profile", "dev", "get", "KEY", "-pp"]),
            ["dotenvx", "--profile", "dev", "get", "KEY", "--pretty-print"]
        );
    }

    #[test]
    fn test_pp_kept_outside_get_flags() {
        let cases: [&[&str]; 5] = [
            &["dotenvx", "set", "KEY", "-pp"],
            &["dotenvx", "set", "KEY", "--", "-pp"],
            &["dotenvx", "get", "KEY", "--", "-pp"],
            &["dotenvx", "get", "--format", "-pp"],
            &["dotenvx", "-c", "echo", "-pp"],
        ];
        for args in cases {
            assert_eq!(normalize(args), args);
        }
    }
}
