use clap::ArgMatches;
use colored::Colorize;
use std::fs::Permissions;
use std::path::{Path, PathBuf};
use symlink::symlink_file;

pub fn link_command(command_matches: &ArgMatches, dotenvx_name: &str) {
    let command_name = command_matches
        .get_one::<String>("command")
        .map(|s| s.as_str())
        .unwrap();
    if command_name.ends_with("venv/bin/python") {
        link_uv_python(command_name);
        return;
    }
    let target_path = PathBuf::from(command_name);
    if target_path.exists() {
        eprintln!("The target path already exists: {}", target_path.display());
        std::process::exit(1);
    }
    if let Some(parent) = target_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    let dotenvx_path = if dotenvx_name.contains("/") || dotenvx_name.contains("\\") {
        PathBuf::from(dotenvx_name)
    } else {
        which::which(dotenvx_name).unwrap()
    };
    symlink_file(dotenvx_path, target_path).unwrap();
    println!(
        "{}",
        format!("${command_name} created and linked to dotenvx executable").green()
    );
}

fn link_uv_python(command_name: &str) {
    let canonical_path = std::fs::canonicalize(command_name).unwrap();
    let real_path = canonical_path.to_string_lossy().to_string();
    std::fs::remove_file(command_name).unwrap();
    let python3_script = format!(
        r#"
#!/bin/bash

# load .env by dotenvx
eval $( dotenvx decrypt --stdout --format shell )
# Execute python3 command with arguments
exec "{real_path}" "$@"
"#
    );
    std::fs::write(command_name, python3_script).unwrap();
    set_executable(command_name);
    println!(
        "{command_name} replaced with dotenvx and python3"
    );
}

#[cfg(unix)]
fn set_executable<P: AsRef<Path>>(path: P) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn set_executable<P: AsRef<Path>>(path: P) {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_resolve_link() {}
}
