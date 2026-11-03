//! End-to-end tests of the `dotenvx` CLI.
//!
//! Every test runs the real binary inside its own temporary sandbox: `HOME` points to a temporary
//! directory and `DOTENVX_DIR` to `$HOME/.dotenvx2` (see AGENTS.md), so no user data is read or
//! written. Profile variables (`NODE_ENV`, ...) and `DOTENV_*` variables of the outer environment
//! are removed so they cannot leak into a test.
#![cfg(unix)]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const PROFILE_ENV_VARS: [&str; 7] = [
    "NODE_ENV",
    "RUN_ENV",
    "APP_ENV",
    "SPRING_PROFILES_ACTIVE",
    "MISE_ENV",
    "STELA_ENV",
    "SECRETSPEC_PROFILE",
];

struct Sandbox {
    _tmp: TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        Sandbox {
            _tmp: tmp,
            home,
            project,
        }
    }

    fn dotenvx_dir(&self) -> PathBuf {
        self.home.join(".dotenvx2")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.project.join(name)
    }

    fn write(&self, name: &str, content: &str) {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.path(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotenvx"));
        cmd.args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("DOTENVX_DIR", self.dotenvx_dir())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        for var in PROFILE_ENV_VARS {
            cmd.env_remove(var);
        }
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("DOTENV_") {
                cmd.env_remove(key);
            }
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("failed to run dotenvx")
    }

    /// Run and assert success, returning stdout.
    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "dotenvx {args:?} failed with {:?}\nstdout: {}\nstderr: {}",
            output.status,
            stdout(&output),
            stderr(&output)
        );
        stdout(&output)
    }

    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Raw (undecoded) value of `key` in a dotenv file content, quotes removed.
fn raw_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn public_key_of(private_key_hex: &str) -> String {
    let sk = ecies::SecretKey::parse_slice(&hex::decode(private_key_hex).unwrap()).unwrap();
    hex::encode(ecies::PublicKey::from_secret_key(&sk).serialize_compressed())
}

fn parse_json(text: &str) -> HashMap<String, String> {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("invalid json ({e}): {text}"))
}

/// `export KEY=...` lines to a map, assumes single-quoted values without embedded quotes.
fn parse_exports(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("export "))
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), v.trim_matches(['\'', '"']).to_string()))
        .collect()
}

// ---------------------------------------------------------------- init

#[test]
fn init_creates_env_file_and_saves_private_key_to_global_store() {
    let sb = Sandbox::new();
    let out = sb.ok(&["init"]);
    assert!(out.contains("Succeed"), "{out}");

    let content = sb.read(".env");
    let public_key = raw_value(&content, "DOTENV_PUBLIC_KEY").expect("public key written");
    assert_eq!(public_key.len(), 66);
    assert!(content.contains("# uuid: "), "{content}");
    assert_eq!(raw_value(&content, "KEY1").as_deref(), Some("value1"));
    // without a local .env.keys the private key goes to $DOTENVX_DIR/.env.keys.json only
    assert!(!sb.path(".env.keys").exists());
    let store = fs::read_to_string(sb.dotenvx_dir().join(".env.keys.json")).unwrap();
    assert!(store.contains(&public_key), "{store}");
    // and the key pair is usable
    let keys = parse_json(&sb.ok(&["keypair"]));
    assert_eq!(keys["DOTENV_PUBLIC_KEY"], public_key);
    assert_eq!(public_key_of(&keys["DOTENV_PRIVATE_KEY"]), public_key);
}

#[test]
fn init_writes_private_key_to_existing_local_env_keys() {
    let sb = Sandbox::new();
    sb.write(".env.keys", "");
    sb.ok(&["init"]);
    let public_key = raw_value(&sb.read(".env"), "DOTENV_PUBLIC_KEY").unwrap();
    let private_key = raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY").unwrap();
    assert_eq!(public_key_of(&private_key), public_key);
}

#[test]
fn init_with_profile_creates_profile_env_file() {
    let sb = Sandbox::new();
    sb.ok(&["-p", "prod", "init"]);
    let content = sb.read(".env.prod");
    assert!(
        raw_value(&content, "DOTENV_PUBLIC_KEY_PROD").is_some(),
        "{content}"
    );
    assert!(!sb.path(".env").exists());
}

#[test]
fn init_does_not_overwrite_env_file_with_public_key() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let before = sb.read(".env");
    let output = sb.run(&["init"]);
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
    assert_eq!(sb.read(".env"), before);
}

#[test]
fn init_stdout_prints_matching_key_pair_without_writing_files() {
    let sb = Sandbox::new();
    let exports = parse_exports(&sb.ok(&["init", "--stdout"]));
    assert_eq!(
        public_key_of(&exports["DOTENV_PRIVATE_KEY"]),
        exports["DOTENV_PUBLIC_KEY"]
    );
    assert_eq!(fs::read_dir(&sb.project).unwrap().count(), 0);
}

#[test]
fn init_global_creates_home_env_keys_with_profiles() {
    let sb = Sandbox::new();
    sb.ok(&["init", "--global"]);
    let keys_file = sb.home.join(".env.keys");
    let content = fs::read_to_string(&keys_file).unwrap();
    for name in [
        "DOTENV_PRIVATE_KEY",
        "DOTENV_PRIVATE_KEY_DEV",
        "DOTENV_PRIVATE_KEY_TEST",
        "DOTENV_PRIVATE_KEY_PROD",
        "DOTENV_PRIVATE_KEY_G_DEFAULT",
    ] {
        let key = raw_value(&content, name).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(key.len(), 64, "{name}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&keys_file).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "$HOME/.env.keys must be owner-only: {mode:o}"
        );
    }
    // running again keeps the existing keys
    let output = sb.run(&["init", "--global"]);
    assert!(stderr(&output).contains("already exists"));
    assert_eq!(fs::read_to_string(&keys_file).unwrap(), content);
}

// ---------------------------------------------------------------- set / get / del

#[test]
fn set_encrypts_sensitive_keys_and_get_decrypts_them() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["set", "HOST_PLAIN", "localhost"]);

    let content = sb.read(".env");
    assert!(
        raw_value(&content, "API_TOKEN")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert!(!content.contains("s3cr3t"));
    // `_PLAIN` keys are never encrypted
    assert_eq!(
        raw_value(&content, "HOST_PLAIN").as_deref(),
        Some("localhost")
    );

    assert_eq!(sb.ok(&["get", "API_TOKEN"]).trim(), r#"API_TOKEN="s3cr3t""#);
    assert_eq!(
        sb.ok(&["get", "HOST_PLAIN"]).trim(),
        r#"HOST_PLAIN="localhost""#
    );
    // key names are normalized: lower case and `-`/`.` become upper case and `_`
    assert_eq!(sb.ok(&["get", "api-token"]).trim(), r#"API_TOKEN="s3cr3t""#);
}

#[test]
fn set_without_init_creates_env_file_and_key_pair() {
    let sb = Sandbox::new();
    let out = sb.ok(&["set", "DB_PASSWORD", "p@ss"]);
    assert!(out.contains("encrypted mode"), "{out}");
    let content = sb.read(".env");
    assert!(raw_value(&content, "DOTENV_PUBLIC_KEY").is_some());
    assert!(
        raw_value(&content, "DB_PASSWORD")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert_eq!(
        sb.ok(&["get", "DB_PASSWORD"]).trim(),
        r#"DB_PASSWORD="p@ss""#
    );
}

#[test]
fn set_plain_and_encrypt_flags_override_detection() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "--plain", "API_TOKEN", "visible"]);
    sb.ok(&["set", "--encrypt", "APP_NAME", "hidden"]);
    let content = sb.read(".env");
    assert_eq!(raw_value(&content, "API_TOKEN").as_deref(), Some("visible"));
    assert!(
        raw_value(&content, "APP_NAME")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert_eq!(sb.ok(&["get", "APP_NAME"]).trim(), r#"APP_NAME="hidden""#);
}

#[test]
fn set_updates_existing_key_in_place_and_keeps_export_prefix() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "--plain", "PORT", "8080"]);
    sb.ok(&["set", "--plain", "PORT", "9090"]);
    let content = sb.read(".env");
    assert_eq!(content.matches("PORT=").count(), 1, "{content}");
    assert_eq!(raw_value(&content, "PORT").as_deref(), Some("9090"));

    let updated = content.replace("PORT=", "export PORT=");
    sb.write(".env", &updated);
    sb.ok(&["set", "--plain", "PORT", "7070"]);
    assert!(
        sb.read(".env").contains(r#"export PORT="7070""#),
        "{}",
        sb.read(".env")
    );
}

#[test]
fn set_value_with_special_characters_round_trips() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let value = r#"a "quoted" $HOME \ value"#;
    sb.ok(&["set", "--plain", "WEIRD", value]);
    let json = parse_json(&sb.ok(&["get", "--format", "json"]));
    assert_eq!(json["WEIRD"], value);
}

#[test]
fn set_reads_value_from_stdin() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let output = sb.run_with_stdin(&["set", "API_TOKEN", "-"], "from-stdin\n");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        sb.ok(&["get", "API_TOKEN"]).trim(),
        r#"API_TOKEN="from-stdin""#
    );
}

#[test]
fn set_stdout_prints_export_line_without_touching_file() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let before = sb.read(".env");
    let out = sb.ok(&["set", "--stdout", "API_TOKEN", "s3cr3t"]);
    let exports = parse_exports(&out);
    assert!(exports["API_TOKEN"].starts_with("encrypted:"), "{out}");
    assert_eq!(sb.read(".env"), before);
    // the printed value can be decrypted with the project key
    assert_eq!(sb.ok(&["decrypt", &exports["API_TOKEN"]]).trim(), "s3cr3t");
}

#[test]
fn set_rejects_invalid_key_names() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let before = sb.read(".env");
    let output = sb.run(&["set", "1BAD", "value"]);
    assert!(
        stderr(&output).contains("Invalid key name"),
        "{}",
        stderr(&output)
    );
    assert_eq!(sb.read(".env"), before);
}

#[test]
fn get_all_entries_in_json_shell_and_csv_formats() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);

    let json = parse_json(&sb.ok(&["get", "--format", "json"]));
    assert_eq!(json["API_TOKEN"], "s3cr3t");
    assert_eq!(json["KEY1"], "value1");

    let shell = parse_exports(&sb.ok(&["get", "--format", "shell"]));
    assert_eq!(shell["API_TOKEN"], "s3cr3t");

    let csv = sb.ok(&["get", "--format", "csv"]);
    assert!(csv.starts_with("key,value\r\n"), "{csv}");
    assert!(csv.contains("API_TOKEN,s3cr3t\r\n"), "{csv}");
}

#[test]
fn get_missing_key_fails() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let output = sb.run(&["get", "MISSING"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not found"));
}

#[test]
fn get_fails_when_private_key_is_missing() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    fs::remove_dir_all(sb.dotenvx_dir()).unwrap();
    let output = sb.run(&["get", "API_TOKEN"]);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(!stdout(&output).contains("encrypted:"));
}

#[test]
fn get_totp_url_adds_one_time_password() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let url = "otpauth://totp/Dotenvx:demo@example.com?secret=VZOQR7AGS6KWMOOKUWFLSTETI74BW4VT&issuer=Dotenvx";
    sb.ok(&["set", "--encrypt", "GITHUB_TOTP", url]);
    let json = parse_json(&sb.ok(&["get", "GITHUB_TOTP", "--format", "json"]));
    assert_eq!(json["GITHUB_TOTP"], url);
    let password = &json["GITHUB_TOTP_PASSWORD"];
    assert_eq!(password.len(), 6, "{password}");
    assert!(password.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn del_removes_key_and_reports_missing_key() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["set", "--plain", "PORT", "8080"]);

    sb.ok(&["del", "API_TOKEN"]);
    let content = sb.read(".env");
    assert!(raw_value(&content, "API_TOKEN").is_none(), "{content}");
    assert_eq!(raw_value(&content, "PORT").as_deref(), Some("8080"));

    let output = sb.run(&["del", "API_TOKEN"]);
    assert!(stderr(&output).contains("not found"));
}

// ---------------------------------------------------------------- encrypt / decrypt

#[test]
fn encrypt_plain_env_file_adds_public_key_and_skips_plain_keys() {
    let sb = Sandbox::new();
    sb.write(
        ".env",
        "# comment\nDB_PASSWORD=pass1\nAPP_NAME_PLAIN=demo\n",
    );
    sb.ok(&["encrypt"]);
    let content = sb.read(".env");
    assert!(
        raw_value(&content, "DOTENV_PUBLIC_KEY").is_some(),
        "{content}"
    );
    assert!(content.contains("# comment"));
    assert!(
        raw_value(&content, "DB_PASSWORD")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert_eq!(
        raw_value(&content, "APP_NAME_PLAIN").as_deref(),
        Some("demo")
    );
    // a new private key was created next to the file
    assert!(raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY").is_some());
    assert_eq!(
        sb.ok(&["get", "DB_PASSWORD"]).trim(),
        r#"DB_PASSWORD="pass1""#
    );

    // encrypting again changes nothing
    let out = sb.ok(&["encrypt"]);
    assert!(out.contains("no changes"), "{out}");
    assert_eq!(sb.read(".env"), content);
}

#[test]
fn encrypt_already_encrypted_file_reports_no_changes() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    // KEY1 from `init` is still plain, encrypt it first
    sb.ok(&["encrypt"]);
    let content = sb.read(".env");
    let out = sb.ok(&["encrypt"]);
    assert!(out.contains("no changes"), "{out}");
    assert_eq!(sb.read(".env"), content);
}

#[test]
fn encrypt_handles_export_prefix() {
    let sb = Sandbox::new();
    sb.write(".env", "export API_TOKEN=secret1\n");
    sb.ok(&["encrypt"]);
    let content = sb.read(".env");
    assert!(!content.contains("secret1"), "{content}");
    assert_eq!(
        sb.ok(&["get", "API_TOKEN"]).trim(),
        r#"API_TOKEN="secret1""#
    );
}

#[test]
fn encrypt_keeps_unrelated_lines_and_values_verbatim() {
    let sb = Sandbox::new();
    let original = [
        "  # indented comment",
        "export API_TOKEN=secret1",
        "  DB_PASSWORD = \"pass\\\"word\"",
        "MULTI_SECRET=\"line1",
        "line2=x\"",
        "APP_NAME_PLAIN=a\\\"b",
        "NOTE=\"has encrypted: inside\"",
    ]
    .join("\n");
    sb.write(".env", &original);
    sb.ok(&["encrypt"]);
    let content = sb.read(".env");
    for kept in [
        "  # indented comment",
        "APP_NAME_PLAIN=a\\\"b",
    ] {
        assert!(content.lines().any(|l| l == kept), "{kept:?} missing in\n{content}");
    }
    assert!(content.contains("export API_TOKEN=\"encrypted:"), "{content}");
    assert!(content.contains("  DB_PASSWORD=\"encrypted:"), "{content}");
    // the multi-line value is replaced as a whole, no `line2` garbage key is left
    assert!(!content.contains("line2=x"), "{content}");
    for secret in ["secret1", "pass\\\"word", "line1"] {
        assert!(!content.contains(secret), "{secret} left in plaintext:\n{content}");
    }
    let json = parse_json(&sb.ok(&["get", "--format", "json"]));
    assert_eq!(json["API_TOKEN"], "secret1");
    assert_eq!(json["DB_PASSWORD"], "pass\"word");
    assert_eq!(json["MULTI_SECRET"], "line1\nline2=x");
    assert_eq!(json["APP_NAME_PLAIN"], "a\"b");
    // a plain value that merely contains `encrypted:` is still encrypted
    assert!(!content.contains("has encrypted: inside"), "{content}");
    assert_eq!(json["NOTE"], "has encrypted: inside");
}

#[test]
fn encrypt_invalid_env_file_fails_without_changes() {
    let sb = Sandbox::new();
    let original = "API_TOKEN=secret1\ngarbage line without separator\n";
    sb.write(".env", original);
    let output = sb.run(&["encrypt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("failed to parse"), "{}", stderr(&output));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
    assert_eq!(sb.read(".env"), original);
}

#[test]
fn decrypt_in_place_keeps_export_prefix() {
    let sb = Sandbox::new();
    sb.write(".env", "export API_TOKEN=secret1\n  DB_PASSWORD=pass1\n");
    sb.ok(&["encrypt"]);
    sb.ok(&["decrypt"]);
    let content = sb.read(".env");
    assert!(content.contains("export API_TOKEN=\"secret1\""), "{content}");
    assert!(content.contains("  DB_PASSWORD=\"pass1\""), "{content}");
    assert!(!content.contains("encrypted:"), "{content}");
}

#[test]
fn encrypt_properties_keeps_plain_values_and_separators() {
    let sb = Sandbox::new();
    sb.write(
        "application.properties",
        "app.name=demo\nserver.port: 8080\ndb.password: secret1\napi.token token1\n",
    );
    sb.ok(&["encrypt"]);
    let content = sb.read("application.properties");
    // non-sensitive values are not quoted or rewritten (Spring would read the quotes)
    assert!(content.lines().any(|l| l == "app.name=demo"), "{content}");
    assert!(content.lines().any(|l| l == "server.port: 8080"), "{content}");
    assert!(content.contains("db.password=encrypted:"), "{content}");
    assert!(content.contains("api.token=encrypted:"), "{content}");
    assert!(!content.contains("secret1") && !content.contains("token1"), "{content}");
    let json = parse_json(&sb.ok(&["decrypt", "--stdout", "--format", "json"]));
    assert_eq!(json["db.password"], "secret1");
    assert_eq!(json["api.token"], "token1");

    sb.ok(&["decrypt"]);
    let content = sb.read("application.properties");
    assert!(content.lines().any(|l| l == "db.password=secret1"), "{content}");
}

#[test]
fn encrypt_only_selected_keys() {
    let sb = Sandbox::new();
    sb.write(".env", "DB_PASSWORD=pass1\nAPI_TOKEN=token1\n");
    sb.ok(&["encrypt", "--keys", "db_password"]);
    let content = sb.read(".env");
    assert!(
        raw_value(&content, "DB_PASSWORD")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert_eq!(raw_value(&content, "API_TOKEN").as_deref(), Some("token1"));
}

#[test]
fn encrypt_stdout_does_not_modify_file() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.write(".env", &format!("{}\nDB_PASSWORD=pass1\n", sb.read(".env")));
    let before = sb.read(".env");
    let out = sb.ok(&["encrypt", "--stdout"]);
    assert!(
        raw_value(&out, "DB_PASSWORD")
            .unwrap()
            .starts_with("encrypted:"),
        "{out}"
    );
    assert_eq!(sb.read(".env"), before);
}

#[test]
fn encrypt_and_get_with_profile_file() {
    let sb = Sandbox::new();
    sb.write(".env.prod", "DB_PASSWORD=prod-pass\n");
    sb.ok(&["encrypt", "-f", ".env.prod"]);
    let content = sb.read(".env.prod");
    assert!(
        raw_value(&content, "DOTENV_PUBLIC_KEY_PROD").is_some(),
        "{content}"
    );
    assert!(raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY_PROD").is_some());
    assert_eq!(
        sb.ok(&["-p", "prod", "get", "DB_PASSWORD"]).trim(),
        r#"DB_PASSWORD="prod-pass""#
    );
    assert_eq!(
        sb.ok(&["get", "-f", ".env.prod", "DB_PASSWORD"]).trim(),
        r#"DB_PASSWORD="prod-pass""#
    );
}

#[test]
fn profile_is_detected_from_environment_variables() {
    let sb = Sandbox::new();
    sb.ok(&["-p", "test", "set", "API_TOKEN", "test-token"]);
    for var in ["NODE_ENV", "APP_ENV", "SPRING_PROFILES_ACTIVE"] {
        let output = sb
            .command(["get", "API_TOKEN"])
            .env(var, "test")
            .output()
            .unwrap();
        assert!(output.status.success(), "{var}: {}", stderr(&output));
        assert_eq!(stdout(&output).trim(), r#"API_TOKEN="test-token""#, "{var}");
    }
}

#[test]
fn decrypt_in_place_and_to_stdout() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["set", "DB_PASSWORD", "pass1"]);
    let encrypted = sb.read(".env");

    let out = sb.ok(&["decrypt", "--stdout"]);
    assert_eq!(raw_value(&out, "API_TOKEN").as_deref(), Some("s3cr3t"));
    assert_eq!(
        sb.read(".env"),
        encrypted,
        "--stdout must not modify the file"
    );

    let json = parse_json(&sb.ok(&["decrypt", "--stdout", "--format", "json"]));
    assert_eq!(json["DB_PASSWORD"], "pass1");

    let shell = sb.ok(&["decrypt", "--stdout", "--format", "shell"]);
    assert_eq!(parse_exports(&shell)["API_TOKEN"], "s3cr3t");

    let dump = parse_json(&sb.ok(&["decrypt", "--dump"]));
    assert_eq!(dump["API_TOKEN"], "s3cr3t");

    let only = parse_json(&sb.ok(&[
        "decrypt",
        "--stdout",
        "--format",
        "json",
        "--keys",
        "api_token",
    ]));
    assert_eq!(only.len(), 1, "{only:?}");
    assert_eq!(only["API_TOKEN"], "s3cr3t");

    sb.ok(&["decrypt"]);
    let decrypted = sb.read(".env");
    assert!(!decrypted.contains("encrypted:"), "{decrypted}");
    assert_eq!(
        raw_value(&decrypted, "API_TOKEN").as_deref(),
        Some("s3cr3t")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(sb.path(".env")).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "decrypted .env must be owner-only: {mode:o}"
        );
    }
}

#[test]
fn decrypt_single_encrypted_value() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    let encrypted = raw_value(&sb.read(".env"), "API_TOKEN").unwrap();
    assert_eq!(sb.ok(&["decrypt", &encrypted]).trim(), "s3cr3t");
}

#[test]
fn decrypt_values_embedded_in_text_file() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    let env = sb.read(".env");
    let public_key = raw_value(&env, "DOTENV_PUBLIC_KEY").unwrap();
    let encrypted = raw_value(&env, "API_TOKEN").unwrap();
    sb.write(
        "config.yaml",
        &format!("# DOTENV_PUBLIC_KEY={public_key}\napi:\n  token: \"{encrypted}\"\n"),
    );
    let out = sb.ok(&["decrypt", "-f", "config.yaml"]);
    assert!(out.contains("token: \"s3cr3t\""), "{out}");
}

/// Serve `body` over HTTP on 127.0.0.1 (one response per connection) and return the base URL.
fn serve_http(body: String) -> String {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) && line != "\r\n" {
                line.clear();
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// review 2.7: a remote file is decrypted with the key matching its own public key, never written back.
#[test]
fn decrypt_remote_env_file() {
    // the remote file is encrypted with another key pair than the local project
    let remote = Sandbox::new();
    remote.write(".env.keys", "");
    remote.write(".env", "API_TOKEN=remote-secret\nPORT=8080\n");
    remote.ok(&["encrypt"]);
    let remote_private_key = raw_value(&remote.read(".env.keys"), "DOTENV_PRIVATE_KEY").unwrap();
    let url = format!("{}/config/.env?token=abc", serve_http(remote.read(".env")));

    let sb = Sandbox::new();
    sb.write(".env.keys", "");
    sb.ok(&["init"]);
    let run = |args: &[&str]| {
        sb.command(args)
            .env("DOTENV_PRIVATE_KEY", &remote_private_key)
            .env("NO_PROXY", "*")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .output()
            .unwrap()
    };

    let output = run(&["decrypt", "-f", &url, "--stdout"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert_eq!(raw_value(&out, "API_TOKEN").as_deref(), Some("remote-secret"), "{out}");
    assert_eq!(raw_value(&out, "PORT").as_deref(), Some("8080"), "{out}");

    let output = run(&["decrypt", "-f", &url, "--stdout", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(parse_json(&stdout(&output))["API_TOKEN"], "remote-secret");

    // without --stdout / --dump: clear error, no panic, nothing written locally
    let before = sb.read(".env");
    let output = run(&["decrypt", "-f", &url]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("--stdout"), "{}", stderr(&output));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
    assert_eq!(sb.read(".env"), before);

    // no matching private key: error instead of panic
    let output = sb.run(&["decrypt", "-f", &url, "--stdout"]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
}

#[test]
fn decrypt_properties_with_lone_quote_value_does_not_panic() {
    let sb = Sandbox::new();
    sb.write("application.properties", "app.name=\"\nquoted=\"demo\"\n");
    let output = sb.run(&["decrypt", "--stdout", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let json = parse_json(&stdout(&output));
    assert_eq!(json["app.name"], "\"");
    assert_eq!(json["quoted"], "demo");
}

#[test]
fn decrypt_in_place_resigns_and_keeps_trailing_newline() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["encrypt", "--sign"]);
    assert!(sb.ok(&["verify"]).contains("is valid"));

    let out = sb.ok(&["decrypt"]);
    assert!(out.contains("signature updated"), "{out}");
    let content = sb.read(".env");
    assert!(content.ends_with('\n'), "{content:?}");
    assert_eq!(raw_value(&content, "API_TOKEN").as_deref(), Some("s3cr3t"));
    assert!(sb.ok(&["verify"]).contains("is valid"));
}

// ---------------------------------------------------------------- sign / verify

#[test]
fn sign_then_verify_and_detect_tampering() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["encrypt", "--sign"]);
    assert!(sb.read(".env").contains("# sign: "), "{}", sb.read(".env"));

    assert!(sb.ok(&["verify"]).contains("is valid"));
    let out = sb.ok(&["decrypt", "--verify"]);
    assert!(out.contains("signature is valid"), "{out}");

    // `set` on a signed file re-signs it
    sb.ok(&["set", "--plain", "PORT", "8080"]);
    assert!(sb.ok(&["verify"]).contains("is valid"));

    // any manual change breaks the signature
    let tampered = sb.read(".env").replace(r#"PORT="8080""#, r#"PORT="9090""#);
    sb.write(".env", &tampered);
    let output = sb.run(&["verify"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("signature is invalid"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn sign_and_verify_profile_file() {
    let sb = Sandbox::new();
    sb.write(".env.prod", "DB_PASSWORD=prod-pass\n");
    sb.ok(&["encrypt", "-f", ".env.prod", "--sign"]);
    assert!(sb.ok(&["verify", "-f", ".env.prod"]).contains("is valid"));
}

/// review #4 (2.1): `.env` only declares `DOTENV_PUBLIC_KEY_PROD`, the header must be added
/// before signing, not inserted in front of the signed content afterward.
#[test]
fn encrypt_sign_with_only_other_profile_public_key_stays_valid() {
    let sb = Sandbox::new();
    sb.ok(&["init", "-f", ".env.prod"]);
    let prod_public_key = raw_value(&sb.read(".env.prod"), "DOTENV_PUBLIC_KEY_PROD").unwrap();
    fs::remove_file(sb.path(".env.prod")).unwrap();
    sb.write(
        ".env",
        &format!("DOTENV_PUBLIC_KEY_PROD=\"{prod_public_key}\"\nB=2\n"),
    );
    sb.ok(&["encrypt", "--sign"]);
    let content = sb.read(".env");
    assert_eq!(content.matches("# ---").count(), 2, "{content}");
    assert_eq!(content.matches("# sign: ").count(), 1, "{content}");
    assert!(
        content.lines().filter(|l| l.starts_with("DOTENV_PUBLIC_KEY=")).count() == 1,
        "{content}"
    );
    assert!(sb.ok(&["verify"]).contains("is valid"));
}

#[test]
fn verify_fails_for_unsigned_or_missing_file() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let output = sb.run(&["verify"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("does not contain a valid signature"));

    let output = sb.run(&["verify", "-f", ".env.missing"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("does not exist"));
}

// ---------------------------------------------------------------- run

#[test]
fn run_injects_decrypted_variables_into_child_process() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    let out = sb.ok(&["run", "--", "sh", "-c", "printf %s \"$API_TOKEN\""]);
    assert_eq!(out, "s3cr3t");
    // `$VAR` arguments are expanded with the injected variables
    let out = sb.ok(&["run", "--", "printf", "%s", "$API_TOKEN"]);
    assert_eq!(out, "s3cr3t");
}

#[test]
fn run_with_env_file_and_profile() {
    let sb = Sandbox::new();
    sb.ok(&["-p", "prod", "set", "API_TOKEN", "prod-token"]);
    let script = "printf %s \"$API_TOKEN\"";
    assert_eq!(
        sb.ok(&["run", "-f", ".env.prod", "--", "sh", "-c", script]),
        "prod-token"
    );
    assert_eq!(
        sb.ok(&["-p", "prod", "run", "--", "sh", "-c", script]),
        "prod-token"
    );
}

#[test]
fn run_propagates_exit_code() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let output = sb.run(&["run", "--", "sh", "-c", "exit 7"]);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn run_without_command_fails() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let output = sb.run(&["run", "--"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("supply command"));
}

#[test]
fn command_flag_runs_command_line_with_injected_variables() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    assert_eq!(sb.ok(&["-c", "printf %s $API_TOKEN"]), "s3cr3t");
    // the command may also be given as several values
    assert_eq!(sb.ok(&["-c", "printf", "%s", "${API_TOKEN}"]), "s3cr3t");
    // with a profile
    sb.ok(&["-p", "prod", "set", "API_TOKEN", "prod-token"]);
    assert_eq!(sb.ok(&["-p", "prod", "-c", "printf %s $API_TOKEN"]), "prod-token");
}

#[test]
fn command_flag_reports_errors_instead_of_panicking() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    for args in [&["-c", "printf 'unbalanced"][..], &["-c", ""][..]] {
        let output = sb.run(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
    }
    let output = sb.run(&["-c", "dotenvx-no-such-command-xyz"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
}

#[test]
fn run_fails_cleanly_when_private_key_is_missing() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    fs::remove_dir_all(sb.dotenvx_dir()).unwrap();
    let output = sb.run(&["run", "--", "sh", "-c", "echo should-not-run"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stdout(&output).contains("should-not-run"));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
}

/// `run` (library) uses the same private key lookup as `decrypt` / `get` (CLI): `.env.keys` next to
/// the env file first, the global key store detected by its top-level `version` field (review 2.5)
#[test]
fn run_uses_same_private_key_lookup_as_cli() {
    let sb = Sandbox::new();
    let (sk, pk) = ecies::utils::generate_keypair();
    let sk_hex = hex::encode(sk.serialize());
    let pk_hex = hex::encode(pk.serialize_compressed());
    let encrypted = dotenvx_rs::encrypt_dotenvx_item(&pk_hex, "sub-secret").unwrap();
    sb.write(
        "sub/.env",
        &format!("DOTENV_PUBLIC_KEY=\"{pk_hex}\"\nAPI_TOKEN=\"{encrypted}\"\n"),
    );
    sb.write("sub/.env.keys", &format!("DOTENV_PRIVATE_KEY=\"{sk_hex}\"\n"));
    let script = "printf %s \"$API_TOKEN\"";
    assert_eq!(sb.ok(&["get", "-f", "sub/.env", "API_TOKEN"]).trim(), r#"API_TOKEN="sub-secret""#);
    assert_eq!(sb.ok(&["run", "-f", "sub/.env", "--", "sh", "-c", script]), "sub-secret");

    // only the global key store (legacy format, a comment mentions "version") has the private key
    fs::remove_file(sb.path("sub/.env.keys")).unwrap();
    fs::create_dir_all(sb.dotenvx_dir()).unwrap();
    fs::write(
        sb.dotenvx_dir().join(".env.keys.json"),
        format!(
            r#"{{"{pk_hex}":{{"public_key":"{pk_hex}","private_key":"{sk_hex}","comment":"\"version\""}}}}"#
        ),
    )
    .unwrap();
    assert_eq!(sb.ok(&["get", "-f", "sub/.env", "API_TOKEN"]).trim(), r#"API_TOKEN="sub-secret""#);
    assert_eq!(sb.ok(&["run", "-f", "sub/.env", "--", "sh", "-c", script]), "sub-secret");

    // without any private key the error tells the reason, not "environment variable not found"
    fs::remove_dir_all(sb.dotenvx_dir()).unwrap();
    let output = sb.run(&["run", "-f", "sub/.env", "--", "sh", "-c", script]);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("Private key not found for public key"), "{err}");
}

// ---------------------------------------------------------------- rotate

#[test]
fn rotate_replaces_key_pair_and_keeps_values() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["set", "HOST_PLAIN", "localhost"]);
    let before = sb.read(".env");
    let old_public_key = raw_value(&before, "DOTENV_PUBLIC_KEY").unwrap();
    let old_cipher = raw_value(&before, "API_TOKEN").unwrap();

    sb.ok(&["rotate"]);
    let after = sb.read(".env");
    let new_public_key = raw_value(&after, "DOTENV_PUBLIC_KEY").unwrap();
    assert_ne!(new_public_key, old_public_key);
    assert_ne!(raw_value(&after, "API_TOKEN").unwrap(), old_cipher);
    assert_eq!(
        raw_value(&after, "HOST_PLAIN").as_deref(),
        Some("localhost")
    );
    assert_eq!(after.lines().count(), before.lines().count());
    assert_eq!(sb.ok(&["get", "API_TOKEN"]).trim(), r#"API_TOKEN="s3cr3t""#);
    let keys = parse_json(&sb.ok(&["keypair"]));
    assert_eq!(keys["DOTENV_PUBLIC_KEY"], new_public_key);
}

#[test]
fn rotate_shared_key_backs_up_old_key_and_warns() {
    let sb = Sandbox::new();
    sb.write(".env.keys", "");
    sb.ok(&["init"]);
    sb.ok(&["set", "ROOT_TOKEN", "root-secret"]);
    let root = sb.read(".env");
    let old_public_key = raw_value(&root, "DOTENV_PUBLIC_KEY").unwrap();
    // sub/.env shares the root key pair and the root .env.keys
    sb.write(
        "sub/.env",
        &format!("DOTENV_PUBLIC_KEY=\"{old_public_key}\"\nPLAIN=1\n"),
    );
    sb.ok(&["set", "-f", "sub/.env", "SUB_TOKEN", "sub-secret"]);
    let old_private_key = raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY").unwrap();

    let output = sb.run(&["rotate", "-f", "sub/.env"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("still used by"), "{err}");
    assert!(err.contains(".env"), "{err}");
    // the root .env.keys got the new key, the old one is kept in the global key store
    assert_ne!(
        raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY").unwrap(),
        old_private_key
    );
    let store = fs::read_to_string(sb.dotenvx_dir().join(".env.keys.json")).unwrap();
    assert!(store.contains(&old_public_key));
    assert!(store.contains(&old_private_key));
    assert_eq!(
        sb.ok(&["get", "ROOT_TOKEN"]).trim(),
        r#"ROOT_TOKEN="root-secret""#
    );
    assert_eq!(
        sb.ok(&["get", "-f", "sub/.env", "SUB_TOKEN"]).trim(),
        r#"SUB_TOKEN="sub-secret""#
    );
}

#[test]
fn rotate_missing_file_fails() {
    let sb = Sandbox::new();
    let output = sb.run(&["rotate"]);
    assert_eq!(output.status.code(), Some(1));
}

// ---------------------------------------------------------------- ls / diff / sync

#[test]
fn ls_lists_env_files_with_metadata() {
    let sb = Sandbox::new();
    assert!(sb.ok(&["ls"]).contains("No .env files found"));

    sb.ok(&["init"]);
    sb.write(".env.prod", "DB_PASSWORD=prod-pass\n");
    sb.ok(&["encrypt", "-f", ".env.prod", "--sign"]);
    sb.write("sub/.env.test", "A=1\n");
    let out = sb.ok(&["ls"]);
    assert!(out.contains("Found 3 .env files"), "{out}");
    for name in [".env ", ".env.prod", "sub/.env.test"] {
        assert!(out.contains(name), "{name} missing in\n{out}");
    }
    // .env.keys is never listed
    assert!(!out.contains(".env.keys"), "{out}");
    let prod_row = out.lines().find(|l| l.contains(".env.prod")).unwrap();
    assert!(prod_row.contains("Yes"), "signed and verified: {prod_row}");

    // filtered by profile
    let out = sb.ok(&["-p", "prod", "ls"]);
    assert!(out.contains("Found 1 .env files"), "{out}");
}

#[test]
fn diff_shows_values_across_profiles() {
    let sb = Sandbox::new();
    sb.ok(&["set", "API_TOKEN", "dev-token"]);
    sb.ok(&["-p", "prod", "set", "API_TOKEN", "prod-token"]);
    sb.ok(&["-p", "prod", "set", "--plain", "PORT", "443"]);
    let out = sb.ok(&["diff", "api_token,port", "--format", "csv"]);
    let mut lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.remove(0), "profile,API_TOKEN,PORT");
    lines.sort();
    assert_eq!(lines, vec![",dev-token,", "prod,prod-token,443"]);

    let table = sb.ok(&["diff", "API_TOKEN"]);
    assert!(
        table.contains("prod-token") && table.contains("dev-token"),
        "{table}"
    );
}

#[test]
fn sync_creates_target_with_new_key_pair_then_adds_missing_keys() {
    let sb = Sandbox::new();
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["set", "--plain", "HOST_PLAIN", "localhost"]);

    sb.ok(&["sync", ".env", ".env.test"]);
    let target = sb.read(".env.test");
    let source_pk = raw_value(&sb.read(".env"), "DOTENV_PUBLIC_KEY").unwrap();
    let target_pk = raw_value(&target, "DOTENV_PUBLIC_KEY_TEST").expect("profile public key");
    assert_ne!(source_pk, target_pk, "target gets its own key pair");
    assert!(
        raw_value(&target, "API_TOKEN")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "API_TOKEN"]).trim(),
        r#"API_TOKEN="s3cr3t""#
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "HOST_PLAIN"]).trim(),
        r#"HOST_PLAIN="localhost""#
    );

    // existing target: only absent keys are appended, existing values are kept
    sb.ok(&["-p", "test", "set", "API_TOKEN", "test-token"]);
    sb.ok(&["set", "NEW_SECRET", "new-value"]);
    let out = sb.ok(&["sync", ".env", ".env.test"]);
    assert!(out.contains("NEW_SECRET"), "{out}");
    assert_eq!(
        sb.ok(&["-p", "test", "get", "NEW_SECRET"]).trim(),
        r#"NEW_SECRET="new-value""#
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "API_TOKEN"]).trim(),
        r#"API_TOKEN="test-token""#
    );
    assert!(sb.ok(&["sync", ".env", ".env.test"]).contains("no changes"));
}

#[test]
fn sync_keeps_encrypted_values_encrypted_in_existing_target() {
    // review 1.2: DATABASE_URL is not a "sensitive" key name, but it is encrypted in the source
    let sb = Sandbox::new();
    sb.write(".env", "DATABASE_URL=postgres://u:pw@h/db\n");
    sb.write(".env.keys", "");
    sb.ok(&["encrypt"]);
    sb.ok(&["init", "-f", ".env.prod"]);
    sb.ok(&["-p", "prod", "set", "--plain", "OTHER", "1"]);

    let out = sb.ok(&["sync", ".env", ".env.prod"]);
    assert!(out.contains("DATABASE_URL"), "{out}");
    let target = sb.read(".env.prod");
    assert!(!target.contains("postgres://"), "{target}");
    assert!(
        raw_value(&target, "DATABASE_URL")
            .unwrap()
            .starts_with("encrypted:"),
        "{target}"
    );
    assert_eq!(
        sb.ok(&["-p", "prod", "get", "DATABASE_URL"]).trim(),
        r#"DATABASE_URL="postgres://u:pw@h/db""#
    );
}

#[test]
fn sync_refuses_encrypted_values_when_target_has_no_public_key() {
    let sb = Sandbox::new();
    sb.write(".env", "DATABASE_URL=postgres://u:pw@h/db\n");
    sb.write(".env.keys", "");
    sb.ok(&["encrypt"]);
    sb.write(".env.prod", "OTHER=1\n");

    let output = sb.run(&["sync", ".env", ".env.prod"]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(stderr(&output).contains("DATABASE_URL"), "{}", stderr(&output));
    assert_eq!(sb.read(".env.prod"), "OTHER=1\n");
}

#[test]
fn sync_new_target_keeps_export_and_multiline_entries() {
    let sb = Sandbox::new();
    sb.write(
        ".env",
        "export DATABASE_URL=postgres://u:pw@h/db # main db\nCERT=\"line1\nline2\"\nHOST=localhost\n",
    );
    sb.write(".env.keys", "");
    sb.ok(&["encrypt"]);
    sb.ok(&["sync", ".env", ".env.test"]);

    let target = sb.read(".env.test");
    assert!(!target.contains("postgres://"), "{target}");
    assert!(!target.contains("line1"), "{target}");
    assert!(
        target.lines().any(|l| l.starts_with("export DATABASE_URL=\"encrypted:")
            && l.ends_with("# main db")),
        "{target}"
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "DATABASE_URL"]).trim(),
        r#"DATABASE_URL="postgres://u:pw@h/db""#
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "CERT"]).trim(),
        r#"CERT="line1\nline2""#
    );
    assert_eq!(
        sb.ok(&["-p", "test", "get", "HOST"]).trim(),
        r#"HOST="localhost""#
    );
}

#[test]
fn sync_without_source_private_key_fails_without_panic() {
    let sb = Sandbox::new();
    sb.write(".env", "DATABASE_URL=postgres://u:pw@h/db\n");
    sb.write(".env.keys", "");
    sb.ok(&["encrypt"]);
    fs::remove_file(sb.path(".env.keys")).unwrap();
    let _ = fs::remove_dir_all(sb.dotenvx_dir());

    let output = sb.run(&["sync", ".env", ".env.test"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
    assert!(!sb.path(".env.test").exists());
}

#[test]
fn sync_missing_source_fails() {
    let sb = Sandbox::new();
    let output = sb.run(&["sync", ".env.none", ".env.test"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!sb.path(".env.test").exists());
}

// ---------------------------------------------------------------- keypair

#[test]
fn keypair_prints_key_pair_in_json_and_shell() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let json = parse_json(&sb.ok(&["keypair"]));
    let shell = parse_exports(&sb.ok(&["keypair", "--format", "shell"]));
    assert_eq!(json, shell);
    assert_eq!(
        public_key_of(&json["DOTENV_PRIVATE_KEY"]),
        json["DOTENV_PUBLIC_KEY"]
    );

    // lookup by public key
    let exports = parse_exports(&sb.ok(&["keypair", &json["DOTENV_PUBLIC_KEY"]]));
    assert_eq!(exports["DOTENV_PRIVATE_KEY"], json["DOTENV_PRIVATE_KEY"]);
    let output = sb.run(&["keypair", "02deadbeef"]);
    assert_eq!(output.status.code(), Some(1));

    // all key pairs of the global store
    let out = sb.ok(&["keypair", "--all"]);
    assert!(out.contains(&json["DOTENV_PUBLIC_KEY"][0..6]), "{out}");
}

#[test]
fn keypair_dump_writes_private_key_next_to_env_file() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let json = parse_json(&sb.ok(&["keypair"]));
    assert!(!sb.path(".env.keys").exists());
    sb.ok(&["keypair", "--dump"]);
    assert_eq!(
        raw_value(&sb.read(".env.keys"), "DOTENV_PRIVATE_KEY").as_deref(),
        Some(json["DOTENV_PRIVATE_KEY"].as_str())
    );
}

#[test]
fn keypair_remove_deletes_key_from_global_store() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let json = parse_json(&sb.ok(&["keypair"]));
    let public_key = &json["DOTENV_PUBLIC_KEY"];
    sb.ok(&["keypair", "--remove", public_key]);
    let store = fs::read_to_string(sb.dotenvx_dir().join(".env.keys.json")).unwrap();
    assert!(!store.contains(public_key.as_str()), "{store}");
    assert_eq!(sb.run(&["keypair", public_key]).status.code(), Some(1));
}

// ---------------------------------------------------------------- global profiles

#[test]
fn global_profile_uses_dotenvx_dir() {
    let sb = Sandbox::new();
    sb.ok(&["init", "--global"]);
    sb.ok(&["-p", "g_default", "set", "GITHUB_TOKEN", "ghp_123"]);
    let global_env = sb.dotenvx_dir().join(".env.g_default");
    let content = fs::read_to_string(&global_env).unwrap();
    assert!(
        raw_value(&content, "GITHUB_TOKEN")
            .unwrap()
            .starts_with("encrypted:")
    );
    assert!(!sb.path(".env.g_default").exists());
    assert_eq!(
        sb.ok(&["-p", "g_default", "get", "GITHUB_TOKEN"]).trim(),
        r#"GITHUB_TOKEN="ghp_123""#
    );
    // the key generated by `init --global` is used, no new key is created
    let private_key = raw_value(
        &fs::read_to_string(sb.home.join(".env.keys")).unwrap(),
        "DOTENV_PRIVATE_KEY_G_DEFAULT",
    )
    .unwrap();
    assert_eq!(
        raw_value(&content, "DOTENV_PUBLIC_KEY_G_DEFAULT"),
        Some(public_key_of(&private_key))
    );
}

// ---------------------------------------------------------------- .properties

#[test]
fn properties_file_encrypt_get_and_decrypt() {
    let sb = Sandbox::new();
    sb.write(
        "application.properties",
        "server.port=8080\ndb.password=secret1\n",
    );
    sb.ok(&["encrypt"]);
    let content = sb.read("application.properties");
    assert!(content.contains("dotenv.public.key="), "{content}");
    assert!(
        raw_value(&content, "db.password")
            .unwrap()
            .starts_with("encrypted:")
    );
    // keys are case sensitive and not normalized in .properties files
    assert_eq!(
        sb.ok(&["get", "db.password"]).trim(),
        r#"db.password="secret1""#
    );

    let json = parse_json(&sb.ok(&["decrypt", "--stdout", "--format", "json"]));
    assert_eq!(json["db.password"], "secret1");
    assert_eq!(json["server.port"], "8080");
}

#[test]
fn properties_file_detected_by_profile() {
    let sb = Sandbox::new();
    sb.write("application-prod.properties", "db.password=prod-secret\n");
    sb.ok(&["-p", "prod", "encrypt"]);
    let content = sb.read("application-prod.properties");
    assert!(content.contains("dotenv.public.key.prod="), "{content}");
    assert_eq!(
        sb.ok(&["-p", "prod", "get", "db.password"]).trim(),
        r#"db.password="prod-secret""#
    );
}

#[test]
fn set_on_properties_file_keeps_key_case() {
    let sb = Sandbox::new();
    sb.write("application.properties", "server.port=8080\n");
    sb.ok(&["set", "spring.datasource.password", "pwd1"]);
    let content = sb.read("application.properties");
    assert!(content.contains("spring.datasource.password="), "{content}");
    assert_eq!(
        sb.ok(&["get", "spring.datasource.password"]).trim(),
        r#"spring.datasource.password="pwd1""#
    );
}

// ---------------------------------------------------------------- misc

#[test]
fn completion_generates_scripts() {
    let sb = Sandbox::new();
    assert!(
        sb.ok(&["completion", "--shell", "bash"])
            .contains("_dotenvx()")
    );
    assert!(
        sb.ok(&["completion", "--shell", "zsh"])
            .starts_with("#compdef dotenvx")
    );
    assert!(
        sb.ok(&["completion", "--shell", "powershell"])
            .contains("dotenvx")
    );
}

#[test]
fn completion_generates_fish_script() {
    let sb = Sandbox::new();
    assert!(
        sb.ok(&["completion", "--shell", "fish"])
            .contains("complete -c dotenvx")
    );
}

#[test]
fn version_and_help() {
    let sb = Sandbox::new();
    let version = sb.ok(&["--version"]);
    assert!(version.contains(env!("CARGO_PKG_VERSION")), "{version}");
    let help = sb.ok(&["--help"]);
    for command in [
        "init", "run", "get", "set", "encrypt", "decrypt", "rotate", "verify",
    ] {
        assert!(help.contains(command), "{command} missing in help");
    }
}

#[test]
fn lint_and_doctor_run_on_project() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    sb.ok(&["set", "API_TOKEN", "s3cr3t"]);
    sb.ok(&["lint"]);
    let out = sb.ok(&["doctor"]);
    assert!(out.contains("Checking .env"), "{out}");
}

#[test]
fn doctor_warns_about_plain_sensitive_values_and_adds_metadata() {
    let sb = Sandbox::new();
    sb.ok(&["init"]);
    let public_key = raw_value(&sb.read(".env"), "DOTENV_PUBLIC_KEY").unwrap();
    // no front matter, a sensitive key with a plain value
    let original = format!("DOTENV_PUBLIC_KEY=\"{public_key}\"\nDB_PASSWORD=plain\n");
    sb.write(".env", &original);
    let output = sb.run(&["doctor"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Sensitive key 'DB_PASSWORD'"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("doctor --fix"), "{}", stderr(&output));
    // doctor only reports, see review #12
    assert_eq!(sb.read(".env"), original);

    let output = sb.run(&["doctor", "--fix"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let content = sb.read(".env");
    assert!(content.starts_with("# ---\n# uuid: "), "{content}");
    assert!(content.contains("DB_PASSWORD=plain"), "{content}");
}

#[test]
fn doctor_fix_resigns_signed_file() {
    let sb = Sandbox::new();
    sb.write(".env", "HELLO=world\n");
    sb.ok(&["encrypt", "--sign"]);
    // a signed file whose front matter has no uuid
    let content: String = sb
        .read(".env")
        .lines()
        .filter(|line| !line.starts_with("# uuid:"))
        .map(|line| format!("{line}\n"))
        .collect();
    sb.write(".env", &content);
    let output = sb.run(&["doctor", "--fix"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let content = sb.read(".env");
    assert_eq!(content.matches("# ---").count(), 2, "{content}");
    assert!(content.contains("# uuid: "), "{content}");
    let output = sb.run(&["verify"]);
    assert!(stdout(&output).contains("is valid"), "{}", stdout(&output));
}

#[test]
fn doctor_warns_about_readable_key_files() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    sb.write(".env.keys", "DOTENV_PRIVATE_KEY=\"00\"\n");
    fs::set_permissions(sb.path(".env.keys"), fs::Permissions::from_mode(0o644)).unwrap();
    let output = sb.run(&["doctor"]);
    assert!(stderr(&output).contains("chmod 600"), "{}", stderr(&output));

    fs::set_permissions(sb.path(".env.keys"), fs::Permissions::from_mode(0o600)).unwrap();
    let output = sb.run(&["doctor"]);
    assert!(
        !stderr(&output).contains("chmod 600"),
        "{}",
        stderr(&output)
    );
}

/// review #9: errors must not exit with 0
#[test]
fn errors_exit_with_non_zero_code() {
    let sb = Sandbox::new();
    // `run -f` with a missing file must not run the command
    let output = sb.run(&["run", "-f", ".env.typo", "--", "echo", "should-not-run"]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("should-not-run"));
    // the default .env is optional for `run`
    assert!(sb.run(&["run", "--", "true"]).status.success());
    // `decrypt -f` with a missing file
    assert!(!sb.run(&["decrypt", "-f", ".env.nope"]).status.success());
    // `decrypt --verify` with an unsigned file
    sb.write(".env", "A=1\n");
    assert!(!sb.run(&["decrypt", "--verify"]).status.success());
    // `lint` with warnings
    sb.write(".env", "A=1\nA=2\n");
    assert!(!sb.run(&["lint"]).status.success());
}
