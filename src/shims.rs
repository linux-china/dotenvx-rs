use crate::commands::decrypt::decrypt_env_entries;
use crate::commands::framework::detect_framework;
use crate::commands::run::get_exit_code;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_env;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Environment variable counting how many shims are currently nested in the process tree.
const SHIM_DEPTH_ENV: &str = "DOTENVX_SHIM_DEPTH";
/// Nesting limit; legit nesting (a shimmed tool calling another shimmed tool) stays far below it.
const MAX_SHIM_DEPTH: u32 = 8;

/// Returns true when the program name is not dotenvx itself, i.e. it is invoked through a shim.
///
/// Renamed binaries such as `dotenvx-aarch64` or `dotenvx_v1.exe` still count as dotenvx.
pub fn is_shim_command(command_name: &str) -> bool {
    let stem = command_name
        .strip_suffix(".exe")
        .unwrap_or(command_name)
        .to_ascii_lowercase();
    !(stem == "dotenvx" || stem.starts_with("dotenvx-") || stem.starts_with("dotenvx_"))
}

/// Reads the current shim depth and returns the value to pass to the child,
/// or `None` when the limit is reached (the shim is most likely re-executing itself).
fn next_shim_depth() -> Option<u32> {
    let depth = env::var(SHIM_DEPTH_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0);
    (depth < MAX_SHIM_DEPTH).then_some(depth + 1)
}

pub fn run_shim(command_name: &str, command_args: &[String]) -> i32 {
    let Some(next_depth) = next_shim_depth() else {
        eprintln!(
            "{}",
            format!(
                "dotenvx shim recursion detected for '{command_name}' ({SHIM_DEPTH_ENV} reached {MAX_SHIM_DEPTH}): the resolved command is probably dotenvx itself (a copy or hard link?)"
            )
            .red()
        );
        return 126;
    };
    if let Some(command_path) = find_command_path(command_name) {
        let _ = dotenvx_rs::dotenv().is_ok();
        let profile = get_profile_name_from_env();
        if let Some(framework) = detect_framework() {
            if framework == "gofr" {
                inject_gofr(&profile);
            } else if framework == "spring-boot" {
                inject_spring_boot(&profile);
            }
        }
        let mut new_command_args: Vec<String> = vec![];
        let mut extra_envs: Vec<(String, String)> = vec![];
        let db_invocation = if command_name == "mysql" || command_name == "mysql.exe" {
            Some(get_mysql_args())
        } else if command_name == "psql" || command_name == "psql.exe" {
            Some(get_psql_args())
        } else if command_name == "redis-cli" || command_name == "redis-cli.exe" {
            Some(get_redis_args())
        } else {
            None
        };
        if let Some(inv) = db_invocation {
            new_command_args.extend(inv.args);
            extra_envs.extend(inv.envs);
        } else if command_name == "mongosh" || command_name == "mongosh.exe" {
            new_command_args.extend(get_mongodb_args());
        } else if command_name == "duckdb" || command_name == "duckdb.exe" {
            // load .env.duckdb file if exists
            if let Ok(current_dir) = env::current_dir() {
                if let Some(dotenv_duck_file) = find_dotenv_duckdb_file_by_path(&current_dir) {
                    dotenvx_rs::from_path(dotenv_duck_file).ok();
                }
            }
            new_command_args.extend(get_duckdb_args());
        }
        if !command_args.is_empty() {
            new_command_args.extend(command_args.to_owned());
        }
        let mut command = Command::new(command_path);
        command
            .envs(env::vars())
            .env(SHIM_DEPTH_ENV, next_depth.to_string())
            .envs(extra_envs)
            .args(&new_command_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .expect("DOTENV-CMD-500: failed to run command");
        let status = child.wait().expect("DOTENV-CMD-500: failed to run command");
        get_exit_code(&status)
    } else {
        eprintln!("Command not found: {command_name}");
        127
    }
}

/// Finds the real executable for `command_name` on `PATH`, skipping any entry that
/// resolves to the running dotenvx binary (symlink chains, hard links).
///
/// The returned path is the `PATH` entry itself, not its canonical target, so
/// multi-call binaries still see the expected `argv[0]`.
pub fn find_command_path(command_name: &str) -> Option<String> {
    let self_exe = env::current_exe().ok();
    let paths = env::var_os("PATH")?;
    let cwd = env::current_dir().ok()?;
    find_command_path_in(command_name, paths, cwd, self_exe.as_deref())
}

fn find_command_path_in<P: AsRef<std::ffi::OsStr>>(
    command_name: &str,
    paths: P,
    cwd: PathBuf,
    self_exe: Option<&Path>,
) -> Option<String> {
    let self_canonical = self_exe.and_then(|p| p.canonicalize().ok());
    which::which_in_all(command_name, Some(paths), cwd)
        .ok()?
        .find(|item| {
            // broken symlinks and unreadable entries are skipped instead of panicking
            let Ok(canonical) = item.canonicalize() else {
                return false;
            };
            match &self_canonical {
                Some(self_path) => !is_same_file(&canonical, self_path),
                None => true,
            }
        })
        .map(|item| item.to_string_lossy().to_string())
}

/// Same canonical path, or (on unix) same device + inode, which also catches hard links.
fn is_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    false
}

fn inject_gofr(profile: &Option<String>) {
    if let Some(profile_name) = profile {
        let dotenv_file = format!("configs/.env.{profile_name}");
        dotenvx_rs::from_path(&dotenv_file).ok();
    } else {
        dotenvx_rs::from_path("configs/.env").ok();
    }
    if let Ok(db_host) = env::var("DB_HOST") {
        let db_dialect = env::var("DB_DIALECT").unwrap_or("mysql".to_string());
        let db_port = env::var("DB_PORT").unwrap_or_else(|_| {
            if db_dialect == "postgres" {
                "5432".to_string()
            } else {
                "3306".to_string()
            }
        });
        let db_name = env::var("DB_NAME").unwrap_or("test".to_string());
        let database_url = format!("{db_dialect}://{db_host}:{db_port}/{db_name}");
        unsafe {
            env::set_var("DATABASE_URL", database_url);
        }
    }
    if let Ok(redis_host) = env::var("REDIS_HOST") {
        let redis_port = env::var("REDIS_PORT").unwrap_or("6379".to_string());
        let redis_db = env::var("REDIS_DB").unwrap_or("0".to_string());
        let schema = if let Ok(redis_ssl) = env::var("REDIS_TLS_ENABLED")
            && redis_ssl == "true"
        {
            "rediss"
        } else {
            "redis"
        };
        let redis_url = format!("{schema}://{redis_host}:{redis_port}/{redis_db}");
        unsafe {
            env::set_var("REDIS_URL", redis_url);
        }
    }
}

fn inject_spring_boot(profile: &Option<String>) {
    let mut all_entries: HashMap<String, String> = HashMap::new();
    if let Ok(entries) = decrypt_env_entries("src/main/resources/application.properties") {
        all_entries.extend(entries);
    }
    if let Some(profile_name) = profile {
        if let Ok(entries) = decrypt_env_entries(&format!(
            "src/main/resources/application-{profile_name}.properties"
        )) {
            all_entries.extend(entries);
        }
    }
    if let Some(datasource_url) = all_entries.get("spring.datasource.url") {
        let mut database_url = datasource_url.as_str();
        if datasource_url.starts_with("jdbc:") {
            database_url = datasource_url.trim_start_matches("jdbc:");
        }
        unsafe {
            env::set_var("DATABASE_URL", database_url);
        }
    }
    if let Some(db_user) = all_entries.get("spring.datasource.username") {
        if !db_user.is_empty() {
            unsafe {
                env::set_var("DB_USER", db_user);
            }
        }
    }
    if let Some(db_password) = all_entries.get("spring.datasource.password") {
        if !db_password.is_empty() {
            unsafe {
                env::set_var("DB_PASSWORD", db_password);
            }
        }
    }
    if let Some(nats_url) = all_entries.get("nats.spring.server") {
        if !nats_url.is_empty() {
            unsafe {
                env::set_var("NATS_URL", nats_url);
            }
        }
    }
    if let Some(redis_url) = all_entries.get("spring.data.redis_url") {
        if !redis_url.is_empty() {
            unsafe {
                env::set_var("REDIS_URL", redis_url);
            }
        }
    } else if let Some(redis_host) = all_entries.get("spring.data.redis_host") {
        let redis_port = "6379".to_string();
        let redis_port = all_entries
            .get("spring.data.redis_port")
            .unwrap_or(&redis_port);
        let redis_db = "0".to_string();
        let redis_db = all_entries
            .get("spring.data.redis_database")
            .unwrap_or(&redis_db);
        let schema = "redis".to_string();
        let schema = if let Some(redis_ssl) = all_entries.get("spring.data.redis.ssl.enabled") {
            if redis_ssl == "true" {
                "rediss".to_string()
            } else {
                schema
            }
        } else {
            schema
        };
        let redis_user = all_entries.get("spring.data.redis.username");
        let redis_password = all_entries.get("spring.data.redis.password");
        let redis_url = if let Some(redis_user) = redis_user {
            if let Some(redis_password) = redis_password {
                format!(
                    "{schema}://{redis_user}:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
                )
            } else {
                format!("{schema}://{redis_user}@{redis_host}:{redis_port}/{redis_db}")
            }
        } else {
            format!("{schema}://{redis_host}:{redis_port}/{redis_db}")
        };
        unsafe {
            env::set_var("REDIS_URL", redis_url);
        }
    }
    if let Some(mongo_uri) = all_entries.get("spring.data.mongodb.uri") {
        if !mongo_uri.is_empty() {
            unsafe {
                env::set_var("MONGODB_URL", mongo_uri);
            }
        }
    } else if let Some(mongo_host) = all_entries.get("spring.data.mongodb.host") {
        let mongo_port = "27017".to_string();
        let mongo_port = all_entries
            .get("spring.data.mongodb.port")
            .unwrap_or(&mongo_port);
        let mongo_db = "test".to_string();
        let mongo_db = all_entries
            .get("spring.data.mongodb.database")
            .unwrap_or(&mongo_db);
        let ssl = "false".to_string();
        let ssl = all_entries
            .get("spring.data.mongodb.ssl.enabled")
            .unwrap_or(&ssl);
        let mongo_user = all_entries.get("spring.data.mongodb.username");
        let mongo_password = all_entries.get("spring.data.mongodb.password");
        let mongo_url = if let Some(mongo_user) = mongo_user {
            if let Some(mongo_password) = mongo_password {
                format!(
                    "mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}/{mongo_db}?ssl={ssl}"
                )
            } else {
                format!("mongodb://{mongo_user}@{mongo_host}:{mongo_port}/{mongo_db}?ssl={ssl}")
            }
        } else {
            format!("mongodb://{mongo_host}:{mongo_port}/{mongo_db}?ssl={ssl}")
        };
        unsafe {
            env::set_var("MONGODB_URL", mongo_url);
        }
    }
}

/// Extra arguments and environment variables a shim adds to the real command.
///
/// Secrets go into `envs`, never `args`: command-line arguments are visible to every
/// local user through `ps` / `/proc/<pid>/cmdline`.
#[derive(Debug, Default, PartialEq, Eq)]
struct ShimInvocation {
    args: Vec<String>,
    envs: Vec<(String, String)>,
}

fn get_mysql_args() -> ShimInvocation {
    let url = env::var("MYSQL_URL").unwrap_or(env::var("DATABASE_URL").unwrap_or_default());
    mysql_invocation(&url, env::var("DB_USER").ok(), env::var("DB_PASSWORD").ok())
}

/// Builds the mysql arguments; the password is passed through `MYSQL_PWD`.
fn mysql_invocation(
    url: &str,
    db_user: Option<String>,
    db_password: Option<String>,
) -> ShimInvocation {
    let mut inv = ShimInvocation::default();
    let url = url.strip_prefix("jdbc:").unwrap_or(url);
    if !(url.starts_with("mysql:") || url.starts_with("mariadb:")) {
        return inv;
    }
    let Ok(parsed_url) = url::Url::parse(url) else {
        return inv;
    };
    if let Some(host) = parsed_url.host_str() {
        inv.args.extend(["-h".to_string(), host.to_string()]);
    }
    if let Some(port) = parsed_url.port() {
        inv.args.extend(["-P".to_string(), port.to_string()]);
    }
    if !parsed_url.username().is_empty() {
        inv.args
            .extend(["-u".to_string(), parsed_url.username().to_string()]);
    } else if let Some(db_user) = db_user {
        inv.args.extend(["-u".to_string(), db_user]);
    }
    if let Some(password) = parsed_url.password().map(str::to_string).or(db_password) {
        inv.envs.push(("MYSQL_PWD".to_string(), password));
    }
    let db_name = parsed_url.path().trim_start_matches('/');
    if !db_name.is_empty() {
        inv.args.push(db_name.to_string());
    }
    inv
}

fn get_psql_args() -> ShimInvocation {
    let url = env::var("POSTGRES_URL").unwrap_or(env::var("DATABASE_URL").unwrap_or_default());
    psql_invocation(&url, env::var("DB_USER").ok(), env::var("DB_PASSWORD").ok())
}

/// Builds the psql arguments; the password is passed through `PGPASSWORD`.
fn psql_invocation(
    url: &str,
    db_user: Option<String>,
    db_password: Option<String>,
) -> ShimInvocation {
    let mut inv = ShimInvocation::default();
    let url = url.strip_prefix("jdbc:").unwrap_or(url);
    if !(url.starts_with("postgres:") || url.starts_with("postgresql:")) {
        return inv;
    }
    let Ok(parsed_url) = url::Url::parse(url) else {
        return inv;
    };
    if let Some(host) = parsed_url.host_str() {
        inv.args.extend(["-h".to_string(), host.to_string()]);
    }
    if let Some(port) = parsed_url.port() {
        inv.args.extend(["-p".to_string(), port.to_string()]);
    }
    if !parsed_url.username().is_empty() {
        inv.args
            .extend(["-U".to_string(), parsed_url.username().to_string()]);
    } else if let Some(db_user) = db_user {
        inv.args.extend(["-U".to_string(), db_user]);
    }
    if let Some(password) = parsed_url.password().map(str::to_string).or(db_password) {
        inv.envs.push(("PGPASSWORD".to_string(), password));
    }
    let db_name = parsed_url.path().trim_start_matches('/');
    if !db_name.is_empty() {
        inv.args.push(db_name.to_string());
    }
    inv
}

fn get_redis_args() -> ShimInvocation {
    let Ok(url) = env::var("REDIS_URL") else {
        return ShimInvocation::default();
    };
    redis_invocation(
        &url,
        env::var("REDIS_USER").ok(),
        env::var("REDIS_PASSWORD").ok(),
    )
}

/// Builds the redis-cli arguments; the password is passed through `REDISCLI_AUTH`.
fn redis_invocation(
    url: &str,
    redis_user: Option<String>,
    redis_password: Option<String>,
) -> ShimInvocation {
    let mut inv = ShimInvocation::default();
    if !(url.starts_with("redis:") || url.starts_with("rediss:")) {
        return inv;
    }
    let Ok(parsed_url) = url::Url::parse(url) else {
        return inv;
    };
    if let Some(host) = parsed_url.host_str() {
        inv.args.extend(["-h".to_string(), host.to_string()]);
    }
    if let Some(port) = parsed_url.port() {
        inv.args.extend(["-p".to_string(), port.to_string()]);
    }
    let username = redis_user.unwrap_or_else(|| parsed_url.username().to_string());
    let password =
        redis_password.unwrap_or_else(|| parsed_url.password().unwrap_or_default().to_string());
    if !username.is_empty() {
        // `-u` is redis-cli's URI option; the ACL user name is `--user`.
        inv.args.extend(["--user".to_string(), username]);
    }
    if !password.is_empty() {
        inv.envs.push(("REDISCLI_AUTH".to_string(), password));
    }
    let db_index = parsed_url.path().trim_start_matches('/');
    if !db_index.is_empty() {
        inv.args.extend(["-n".to_string(), db_index.to_string()]);
    }
    inv
}

fn get_mongodb_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    if let Ok(mongodb_url) = env::var("MONGODB_URL") {
        if mongodb_url.starts_with("mongodb:") || mongodb_url.starts_with("mongodbs:") {
            args.push(mongodb_url.to_string());
        }
    }
    args
}

pub struct DuckSecret {
    pub name: String,
    pub obj_type: String,
    pub child_type: Option<String>,
    pub variables: HashMap<String, String>,
}

impl DuckSecret {
    fn from_env(name: String) -> Option<Self> {
        let obj_prefix = format!("DUCKDB__{name}__");
        let child_type_key = format!("{obj_prefix}TYPE");
        if let Ok(obj_type) = env::var(format!("DUCKDB__{name}")) {
            let child_type = env::var(&child_type_key).ok();
            let mut db_obj = DuckSecret {
                name: name.to_lowercase(),
                obj_type,
                child_type,
                variables: HashMap::new(),
            };
            for (key, value) in env::vars() {
                if key.starts_with(&obj_prefix) && key != child_type_key {
                    let var_key = key.trim_start_matches(&obj_prefix).to_string();
                    db_obj.variables.insert(var_key, value);
                }
            }
            if !db_obj.variables.is_empty() {
                return Some(db_obj);
            }
        }
        None
    }

    fn to_sql(&self) -> Option<String> {
        let child_type = self.child_type.as_deref();
        if self.obj_type == "secret" && !self.variables.is_empty() {
            let variables = self
                .variables
                .iter()
                .map(|(k, v)| format!("{} '{}'", k, v.replace('\'', "''")))
                .collect::<Vec<String>>()
                .join(", ");
            return Some(format!(
                "CREATE SECRET {} ( TYPE {}, {});",
                self.name,
                child_type.unwrap(),
                variables
            ));
        } else if self.obj_type == "attach" && !self.variables.is_empty() {
            let mut db_variables = self.variables.clone();
            let db_url = db_variables.remove("URL").unwrap_or_default();
            if db_variables.is_empty() {
                return if let Some(child_type_text) = child_type {
                    Some(format!(
                        "ATTACH '{}' AS {} (TYPE {});",
                        db_url.trim_matches('\''),
                        self.name,
                        child_type_text
                    ))
                } else {
                    Some(format!(
                        "ATTACH '{}' AS {};",
                        db_url.trim_matches('\''),
                        self.name,
                    ))
                };
            } else {
                let other_variables = db_variables
                    .iter()
                    .map(|(k, v)| {
                        if v == "true" || v == "false" {
                            format!("{k} {v}")
                        } else {
                            format!("{k} '{v}'")
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                return if let Some(child_type_text) = child_type {
                    Some(format!(
                        "ATTACH '{}' AS {} (TYPE {}, {});",
                        db_url.trim_matches('\''),
                        self.name,
                        child_type_text,
                        other_variables
                    ))
                } else {
                    Some(format!(
                        "ATTACH '{}' AS {} ({});",
                        db_url.trim_matches('\''),
                        self.name,
                        other_variables
                    ))
                };
            }
        }
        None
    }
}
fn get_duckdb_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    let mut obj_names: Vec<String> = Vec::new();
    let mut misc_sql_sentences: Vec<String> = Vec::new();
    let mut encrypt_db_included = false;
    for (key, value) in env::vars() {
        if key.starts_with("DUCKDB__PARQUET__") {
            // https://duckdb.org/docs/stable/data/parquet/encryption
            let parquet_key_name = key
                .strip_prefix("DUCKDB__PARQUET__")
                .unwrap()
                .to_lowercase();
            misc_sql_sentences.push(format!(
                "PRAGMA add_parquet_key('{parquet_key_name}', '{value}');"
            ));
        } else if key.starts_with("DUCKDB__ENCRYPTED__") {
            // https://duckdb.org/docs/stable/sql/statements/attach#database-encryption
            let db_name = key
                .strip_prefix("DUCKDB__ENCRYPTED__")
                .unwrap()
                .to_lowercase();
            let parts = value.split('@').collect::<Vec<&str>>();
            let aes_key = parts.first().unwrap();
            let db_path = parts.get(1).unwrap();
            // SQL example: "ATTACH 'encrypted.db' AS enc_db (ENCRYPTION_KEY 'quack_quack');"
            misc_sql_sentences.push(format!(
                "ATTACH '{db_path}' AS {db_name} (ENCRYPTION_KEY '{aes_key}');"
            ));
            encrypt_db_included = true;
        } else if key.starts_with("DUCKDB__DUCKLAKE__") {
            // https://duckdb.org/docs/stable/sql/statements/attach#database-encryption
            let db_name = key
                .strip_prefix("DUCKDB__DUCKLAKE__")
                .unwrap()
                .to_lowercase();
            let mut ducklake_options = "".to_owned();
            let mut catalog_db_url = if let Some(pos) = value.find('(') {
                ducklake_options = value[pos + 1..value.len() - 1].to_owned();
                value[pos + 1..].to_owned()
            } else {
                value.clone()
            };
            if !catalog_db_url.starts_with("'") {
                catalog_db_url = format!("'{catalog_db_url}'");
            }
            // SQL example: "ATTACH 'encrypted.db' AS enc_db (ENCRYPTION_KEY 'quack_quack');"
            misc_sql_sentences.push(format!(
                "ATTACH {catalog_db_url} AS {db_name} {ducklake_options};"
            ));
        } else if key.starts_with("DUCKDB__") {
            if let Some(secret_name) = key.split("__").nth(1) {
                let name = secret_name.to_string();
                if !obj_names.contains(&name) {
                    obj_names.push(name);
                }
            }
        }
    }
    if encrypt_db_included {
        // OpenSSL versions are much faster due to hardware acceleration
        misc_sql_sentences.push("LOAD httpfs;".to_string());
    }
    if !misc_sql_sentences.is_empty() {
        args.push("--cmd".to_string());
        args.push(misc_sql_sentences.join(" "));
    }
    if !obj_names.is_empty() {
        for secret_name in obj_names {
            if let Some(duck_obj) = DuckSecret::from_env(secret_name) {
                if duck_obj.obj_type == "secret" {
                    println!("{} secret of '{}' created.", "✔ ".green(), duck_obj.name);
                } else if duck_obj.obj_type == "attach" {
                    println!("{} database of '{}' attached.", "✔ ".green(), duck_obj.name);
                }
                if let Some(sql) = duck_obj.to_sql() {
                    args.push("--cmd".to_string());
                    args.push(sql);
                }
            }
        }
    }
    args
}

pub fn find_dotenv_duckdb_file_by_path(dir: &Path) -> Option<PathBuf> {
    if dir.join(".env.duckdb").exists() {
        return Some(dir.join(".env.duckdb"));
    } else if let Some(parent) = dir.parent() {
        return find_dotenv_duckdb_file_by_path(parent);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_command_path() {
        let path = find_command_path("sh");
        println!("Found command path: {:?}", path);
        assert!(path.is_some());
    }

    #[test]
    fn test_is_shim_command() {
        for name in ["dotenvx", "dotenvx.exe", "dotenvx-aarch64", "dotenvx_v1.exe", "DotEnvX"] {
            assert!(!is_shim_command(name), "{name} should be dotenvx itself");
        }
        for name in ["mysql", "psql.exe", "redis-cli", "python", "mydotenvx"] {
            assert!(is_shim_command(name), "{name} should be a shim");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_find_command_path_skips_self() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let exe = |p: &Path| {
            std::fs::write(p, "#!/bin/sh\n").unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        // fake dotenvx binary
        let dotenvx = root.join("dotenvx");
        exe(&dotenvx);
        // shims: multi-level symlink, hard link, broken symlink
        let (a, b, c, d, real) = (
            root.join("a"),
            root.join("b"),
            root.join("c"),
            root.join("d"),
            root.join("real"),
        );
        for dir in [&a, &b, &c, &d, &real] {
            std::fs::create_dir(dir).unwrap();
        }
        symlink(&dotenvx, root.join("mysql-shim")).unwrap();
        symlink(root.join("mysql-shim"), a.join("mysql")).unwrap();
        std::fs::hard_link(&dotenvx, b.join("mysql")).unwrap();
        symlink(root.join("missing"), c.join("mysql")).unwrap();
        exe(&real.join("mysql"));
        let paths = std::env::join_paths([&a, &b, &c, &real]).unwrap();
        let found = find_command_path_in("mysql", &paths, root.clone(), Some(&dotenvx));
        assert_eq!(found, Some(real.join("mysql").to_string_lossy().to_string()));
        // only dotenvx entries -> not found
        let paths = std::env::join_paths([&a, &b, &c, &d]).unwrap();
        assert_eq!(find_command_path_in("mysql", &paths, root, Some(&dotenvx)), None);
    }

    fn env_pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    fn has_secret(inv: &ShimInvocation, secret: &str) -> bool {
        inv.args.iter().any(|a| a.contains(secret))
    }

    #[test]
    fn test_mysql_password_not_in_args() {
        let inv = mysql_invocation("jdbc:mysql://root:s3cret@db:3306/app", None, None);
        assert_eq!(inv.args, ["-h", "db", "-P", "3306", "-u", "root", "app"]);
        assert_eq!(inv.envs, [env_pair("MYSQL_PWD", "s3cret")]);
        // fallback to DB_USER / DB_PASSWORD
        let inv = mysql_invocation("mysql://db/app", Some("u".into()), Some("fallback".into()));
        assert!(!has_secret(&inv, "fallback"));
        assert_eq!(inv.envs, [env_pair("MYSQL_PWD", "fallback")]);
        assert!(mysql_invocation("postgres://db/app", None, None) == ShimInvocation::default());
    }

    #[test]
    fn test_psql_password_not_in_args() {
        let inv = psql_invocation("postgres://pg:s3cret@db:5432/app", None, None);
        assert_eq!(inv.args, ["-h", "db", "-p", "5432", "-U", "pg", "app"]);
        assert_eq!(inv.envs, [env_pair("PGPASSWORD", "s3cret")]);
    }

    #[test]
    fn test_redis_password_not_in_args() {
        let inv = redis_invocation("redis://alice:s3cret@cache:6380/2", None, None);
        assert_eq!(
            inv.args,
            ["-h", "cache", "-p", "6380", "--user", "alice", "-n", "2"]
        );
        assert_eq!(inv.envs, [env_pair("REDISCLI_AUTH", "s3cret")]);
        // password only, overridden by REDIS_PASSWORD
        let inv = redis_invocation("redis://:old@cache", None, Some("new".into()));
        assert_eq!(inv.args, ["-h", "cache"]);
        assert_eq!(inv.envs, [env_pair("REDISCLI_AUTH", "new")]);
        // no credentials
        let inv = redis_invocation("redis://cache", None, None);
        assert!(inv.envs.is_empty());
    }

    #[test]
    fn test_url_parse() {
        let url = "postgres://user:password@localhost:5432/mydb";
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.scheme(), "postgres");
        assert_eq!(parsed.username(), "user");
        assert_eq!(parsed.password().unwrap(), "password");
        assert_eq!(parsed.host_str().unwrap(), "localhost");
        assert_eq!(parsed.port().unwrap(), 5432);
        assert_eq!(parsed.path(), "/mydb");
    }

    #[test]
    fn test_url2_parse() {
        let url = "redis://password1@localhost:4392/2";
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.username(), "password1");
    }

    #[test]
    fn test_duckdb() {
        unsafe {
            env::set_var("DUCKDB__S3_SECRET", "secret");
            env::set_var("DUCKDB__S3_SECRET__TYPE", "s3");
            env::set_var("DUCKDB__S3_SECRET__KEY_ID", "1111");
            env::set_var("DUCKDB__S3_SECRET__SECRET", "password");
            env::set_var("DUCKDB__HTTP_SECRET", "secret");
            env::set_var("DUCKDB__HTTP_SECRET__TYPE", "http");
            env::set_var("DUCKDB__HTTP_SECRET__BEARER_TOKEN", "xxxx");
            // encryption database
            env::set_var("DUCKDB__SAKILA", "attach");
            env::set_var("DUCKDB__SAKILA__TYPE", "sqlite");
            env::set_var("DUCKDB__SAKILA__URL", "sakila.sqlite3");
            env::set_var("DUCKDB__SAKILA__ENCRYPTION_KEY", "123456");
            // datalake
            env::set_var("DUCKDB__LAKE1", "attach");
            env::set_var(
                "DUCKDB__LAKE1__URL",
                "ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=postgres password=123456",
            );
            env::set_var("DUCKDB__LAKE1__DATA_PATH", "s3://lake1");
        }
        let args = get_duckdb_args();
        for arg in args {
            println!("{arg}");
        }
    }
}
