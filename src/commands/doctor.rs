use crate::commands::crypt_util::write_file_atomic;
use crate::commands::encrypt::add_or_replace_signature;
use crate::commands::model::{extract_front_matter, get_signature};
use crate::commands::linter::lint;
use crate::commands::{
    entry_line_count, get_dotenvx_home, get_public_key_name_for_file, is_encrypted_value_text,
    is_sensitive_key, list_env_files, split_assignment,
};
use clap::ArgMatches;
use colored::Colorize;
use std::env::current_dir;
use std::path::{Path, PathBuf};

pub fn doctor_command(command_matches: &ArgMatches) {
    let fix = command_matches.get_flag("fix");
    check_key_files_permissions();
    let current_dir = current_dir().unwrap();
    let env_files = list_env_files(current_dir, 1, &None);
    for env_file in env_files {
        let file_name = env_file.file_name().to_str().unwrap();
        let file_path = env_file.path();
        println!("Checking {file_name}:");
        let file_content = match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("{}", format!("Warning: failed to read {file_name}: {e}").red());
                continue;
            }
        };
        let report = check_env_content(file_name, &file_content);
        if !report.public_key_found {
            eprintln!(
                "{}",
                format!("Warning: no public key found in {file_name}").red()
            );
            continue;
        }
        for warning in &report.key_warnings {
            eprintln!("{}", warning.red());
        }
        // check front matter: report only, `--fix` writes the file, see review #12
        if !has_front_matter_id(&file_content) {
            if fix {
                fix_front_matter(file_name, file_path, &file_content);
            } else {
                eprintln!(
                    "{}",
                    format!(
                        "Warning: no metadata(front matter) uuid in {file_name}, run `dotenvx doctor --fix` to add it."
                    )
                    .yellow()
                );
            }
        }
    }
    println!();
    println!("Run linter now...");
    if let Err(e) = lint() {
        eprintln!("{}", format!("Warning: failed to lint env files: {e}").red());
    }
}

/// Result of checking the content of one env file.
#[derive(Debug, Default)]
struct EnvCheckReport {
    /// Whether a `DOTENV_PUBLIC_KEY*` (`dotenv.public.key*` for `.properties`) entry exists.
    public_key_found: bool,
    /// Warnings about the public key name and sensitive keys with plain values.
    key_warnings: Vec<String>,
}

/// Normalize a key name for public key detection: `.properties` keys use `dotenv.public.key`.
fn is_public_key_name(key: &str) -> bool {
    key.to_uppercase()
        .replace('.', "_")
        .starts_with("DOTENV_PUBLIC_KEY")
}

/// Check the content of an env file entry by entry: `export ` prefixes and `.properties` syntax
/// are understood, and continuation lines of multi-line values are skipped.
fn check_env_content(file_name: &str, content: &str) -> EnvCheckReport {
    let mut report = EnvCheckReport::default();
    let expected_public_key_name = get_public_key_name_for_file(file_name);
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line_count = entry_line_count(file_name, &lines, i).max(1);
        if let Some((_, key, value_text)) = split_assignment(file_name, lines[i]) {
            if is_public_key_name(key) {
                if !report.public_key_found && key != expected_public_key_name {
                    report.key_warnings.push(format!(
                        "Warning: The public key in {file_name} does not match the expected format: {expected_public_key_name}"
                    ));
                }
                report.public_key_found = true;
            } else if !is_encrypted_value_text(value_text) && is_sensitive_key(key) {
                report.key_warnings.push(format!(
                    "Warning: Sensitive key '{}' in {file_name} has a plain value.",
                    key.to_uppercase()
                ));
            }
        }
        i += line_count;
    }
    report
}

/// Whether the file starts with a front matter block that declares `uuid` or `id`.
/// Only the leading `# ---` block counts, so values containing `# id:` do not.
fn has_front_matter_id(content: &str) -> bool {
    let metadata = extract_front_matter(content);
    metadata.contains_key("uuid") || metadata.contains_key("id")
}

/// Return `content` with a `# uuid:` entry: inserted into the existing leading front matter block,
/// or as a new front matter block at the top when the file has none.
fn add_front_matter_uuid(content: &str, uuid: &str) -> String {
    let is_marker = |line: &str| line.starts_with("# ---") || line.starts_with("#---");
    let lines: Vec<&str> = content.lines().collect();
    if lines.first().is_some_and(|line| is_marker(line))
        && let Some(end) = lines[1..].iter().position(|line| is_marker(line))
    {
        let mut new_lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
        new_lines.insert(end + 1, format!("# uuid: {uuid}"));
        let mut new_content = new_lines.join("\n");
        if content.ends_with('\n') {
            new_content.push('\n');
        }
        return new_content;
    }
    format!("# ---\n# uuid: {uuid}\n# name: app_name\n# group: group_name\n# ---\n{content}")
}

/// Add the missing front matter uuid to `file_path` atomically. A signed file is re-signed in
/// memory before writing; when it cannot be re-signed the file is left untouched.
fn fix_front_matter(file_name: &str, file_path: &Path, file_content: &str) {
    let env_file_uuid = uuid::Uuid::now_v7().to_string();
    let mut new_content = add_front_matter_uuid(file_content, &env_file_uuid);
    if get_signature(file_content).is_some() {
        let env_file = file_path.to_string_lossy();
        match add_or_replace_signature(&env_file, &new_content) {
            Ok(signed) => new_content = signed,
            Err(e) => {
                eprintln!(
                    "{}",
                    format!(
                        "Warning: {file_name} is signed but can not be re-signed, skip fixing: {e}"
                    )
                    .red()
                );
                return;
            }
        }
        if !new_content.ends_with('\n') {
            new_content.push('\n');
        }
    }
    match write_file_atomic(file_path, new_content.as_bytes()) {
        Ok(()) => println!(
            "{}",
            format!("✔ metadata added to {file_name} with uuid: {env_file_uuid}").green()
        ),
        Err(e) => eprintln!(
            "{}",
            format!("Warning: failed to add metadata to {file_name}: {e}").red()
        ),
    }
}

/// Collect the sensitive key/secret files that should be owner-only (0600).
fn sensitive_key_files() -> Vec<PathBuf> {
    let mut files = vec![];
    files.push(get_dotenvx_home().join(".env.keys.json"));
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".env.keys"));
    }
    if let Ok(dir) = current_dir() {
        files.push(dir.join(".env.keys"));
    }
    files
}

/// Warn when a sensitive key file is readable/writable by group or others (Unix only).
fn check_key_files_permissions() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        println!("Checking key file permissions:");
        for file in sensitive_key_files() {
            if !file.exists() {
                continue;
            }
            if let Ok(metadata) = std::fs::metadata(&file) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    eprintln!(
                        "{}",
                        format!(
                            "Warning: {} has permissions {:o}, group/other can access it. Run `chmod 600 {}`.",
                            file.display(),
                            mode,
                            file.display()
                        )
                        .red()
                    );
                } else {
                    println!("✔ {} ({:o})", file.display(), mode);
                }
            }
        }
        println!();
    }
    #[cfg(not(unix))]
    {
        // File mode checks are not applicable on non-Unix platforms.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_env_content_export_public_key() {
        let report = check_env_content(".env", "export DOTENV_PUBLIC_KEY=\"02ab\"\nA=1\n");
        assert!(report.public_key_found);
        assert!(report.key_warnings.is_empty());
    }

    #[test]
    fn test_check_env_content_properties() {
        let content = "dotenv.public.key.properties=02ab\ndb.password=encrypted:xx\napp.token: plain\n";
        let report = check_env_content(".env.properties", content);
        assert!(report.public_key_found);
        assert_eq!(report.key_warnings.len(), 1, "{:?}", report.key_warnings);
        assert!(report.key_warnings[0].contains("APP.TOKEN"));
    }

    #[test]
    fn test_check_env_content_multiline_value() {
        // continuation lines that look like `KEY=value` must not be checked as entries
        let content = "DOTENV_PUBLIC_KEY=\"02ab\"\nCERT=\"line1\nPRIVATE_KEY=inside\n\"\nAPI_TOKEN=\"encrypted:xx\"\nDB_PASSWORD=plain\n";
        let report = check_env_content(".env", content);
        assert!(report.public_key_found);
        assert_eq!(report.key_warnings.len(), 1, "{:?}", report.key_warnings);
        assert!(report.key_warnings[0].contains("DB_PASSWORD"));
    }

    #[test]
    fn test_check_env_content_wrong_public_key_name() {
        let report = check_env_content(".env.prod", "DOTENV_PUBLIC_KEY=\"02ab\"\n");
        assert!(report.public_key_found);
        assert!(report.key_warnings[0].contains("DOTENV_PUBLIC_KEY_PROD"));
        assert!(!check_env_content(".env", "A=1\n").public_key_found);
    }

    #[test]
    fn test_has_front_matter_id() {
        assert!(has_front_matter_id("# ---\n# uuid: abc\n# ---\nA=1\n"));
        assert!(has_front_matter_id("# ---\n# id: abc\n# ---\nA=1\n"));
        // `# id:` outside the front matter does not count
        assert!(!has_front_matter_id("A=1\nB=\"# id: x\"\n# uuid: y\n"));
        assert!(!has_front_matter_id("# ---\n# name: app\n# ---\nA=1\n"));
    }

    #[test]
    fn test_add_front_matter_uuid_without_front_matter() {
        let content = add_front_matter_uuid("A=1\n", "u1");
        assert!(content.starts_with("# ---\n# uuid: u1\n"));
        assert!(content.ends_with("# ---\nA=1\n"));
        assert!(has_front_matter_id(&content));
    }

    #[test]
    fn test_add_front_matter_uuid_into_existing_block() {
        let content = add_front_matter_uuid("# ---\n# name: app\n# sign: xx\n# ---\nA=1\n", "u1");
        assert_eq!(
            content,
            "# ---\n# name: app\n# sign: xx\n# uuid: u1\n# ---\nA=1\n"
        );
    }
}
