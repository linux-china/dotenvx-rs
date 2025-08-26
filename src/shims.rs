use std::env;
use std::process::{Command, Stdio};

pub fn is_shim_command(command_name: &str) -> bool {
    !(command_name == "dotenvx" || command_name == "dotenvx.exe")
}

pub fn run_shim(command_name: &str, command_args: &[String]) -> i32 {
    if let Some(command_path) = find_command_path(command_name) {
        let _ = dotenvx_rs::dotenv().is_ok();
        let mut command = Command::new(command_path);
        command
            .envs(env::vars())
            .args(command_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .expect("DOTENV-CMD-500: failed to run command");
        child
            .wait()
            .expect("DOTENV-CMD-500: failed to run command")
            .code()
            .unwrap()
    } else {
        eprintln!("Command not found: {command_name}");
        127
    }
}

pub fn find_command_path(command_name: &str) -> Option<String> {
    if let Ok(items) = which::which_all(command_name) {
        for item in items {
            if item.is_symlink() {
                if let Ok(target) = std::fs::read_link(&item) {
                    let file_name = target.file_name().unwrap().to_str().unwrap().to_owned();
                    if !(file_name == "dotenvx" || file_name == "dotenvx.exe") {
                        let absolute_target = if target.is_absolute() {
                            target.canonicalize().unwrap()
                        } else {
                            item.parent()
                                .ok_or("No parent directory")
                                .unwrap()
                                .join(target)
                                .canonicalize()
                                .unwrap()
                        };
                        return Some(absolute_target.to_string_lossy().to_string());
                    }
                }
            } else {
                return Some(item.to_string_lossy().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_command_path() {
        let path = find_command_path("lua");
        println!("Found command path: {:?}", path);
        assert!(path.is_some());
    }
}
