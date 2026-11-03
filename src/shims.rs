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

/// The shim still runs the wrapped command, but a load/decrypt failure must not be silent (review #9).
fn warn_load_error(env_file: &str, result: dotenvy::Result<()>) {
    if let Err(e) = result {
        eprintln!(
            "{}",
            format!("dotenvx shim: failed to load {env_file}, the variables are not injected: {e}")
                .yellow()
        );
    }
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
        warn_load_error(".env", dotenvx_rs::dotenv());
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
                    let result = dotenvx_rs::from_path(&dotenv_duck_file);
                    warn_load_error(&dotenv_duck_file.display().to_string(), result);
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
        match command.spawn().and_then(|mut child| child.wait()) {
            Ok(status) => get_exit_code(&status),
            Err(e) => {
                eprintln!("DOTENV-CMD-500: failed to run command {command_name}: {e}");
                1
            }
        }
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
        warn_load_error(&dotenv_file, dotenvx_rs::from_path(&dotenv_file));
    } else {
        warn_load_error("configs/.env", dotenvx_rs::from_path("configs/.env"));
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
    if let Some(redis_url) = spring_redis_url(&all_entries) {
        unsafe {
            env::set_var("REDIS_URL", redis_url);
        }
    }
    if let Some(mongo_url) = spring_mongodb_url(&all_entries) {
        unsafe {
            env::set_var("MONGODB_URL", mongo_url);
        }
    }
}

/// Characters kept as-is in a URL user name or password: RFC 3986 unreserved characters.
const USERINFO_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes a URL user name or password, e.g. `p@ss` becomes `p%40ss`.
fn url_encode_userinfo(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, USERINFO_ENCODE_SET).to_string()
}

/// Builds the `user:password@` part of a URL; empty when neither is set.
fn userinfo(user: Option<&String>, password: Option<&String>) -> String {
    let user = user
        .filter(|u| !u.is_empty())
        .map(|u| url_encode_userinfo(u));
    let password = password
        .filter(|p| !p.is_empty())
        .map(|p| url_encode_userinfo(p));
    match (user, password) {
        (Some(user), Some(password)) => format!("{user}:{password}@"),
        (Some(user), None) => format!("{user}@"),
        (None, Some(password)) => format!(":{password}@"),
        (None, None) => String::new(),
    }
}

/// Redis URL from Spring Boot's `spring.data.redis.*` properties.
fn spring_redis_url(entries: &HashMap<String, String>) -> Option<String> {
    if let Some(url) = entries
        .get("spring.data.redis.url")
        .filter(|u| !u.is_empty())
    {
        return Some(url.clone());
    }
    let host = entries
        .get("spring.data.redis.host")
        .filter(|h| !h.is_empty())?;
    let port = entries
        .get("spring.data.redis.port")
        .map_or("6379", String::as_str);
    let db = entries
        .get("spring.data.redis.database")
        .map_or("0", String::as_str);
    let schema = match entries.get("spring.data.redis.ssl.enabled") {
        Some(ssl) if ssl == "true" => "rediss",
        _ => "redis",
    };
    // Redis ACL users are optional: `redis://:password@host` authenticates as `default`.
    let auth = userinfo(
        entries.get("spring.data.redis.username"),
        entries.get("spring.data.redis.password"),
    );
    Some(format!("{schema}://{auth}{host}:{port}/{db}"))
}

/// MongoDB URL from Spring Boot's `spring.data.mongodb.*` properties.
fn spring_mongodb_url(entries: &HashMap<String, String>) -> Option<String> {
    if let Some(uri) = entries
        .get("spring.data.mongodb.uri")
        .filter(|u| !u.is_empty())
    {
        return Some(uri.clone());
    }
    let host = entries
        .get("spring.data.mongodb.host")
        .filter(|h| !h.is_empty())?;
    let port = entries
        .get("spring.data.mongodb.port")
        .map_or("27017", String::as_str);
    let db = entries
        .get("spring.data.mongodb.database")
        .map_or("test", String::as_str);
    let ssl = entries
        .get("spring.data.mongodb.ssl.enabled")
        .map_or("false", String::as_str);
    // MongoDB has no password-only auth, so a password without a user name is dropped.
    let user = entries.get("spring.data.mongodb.username");
    let password = user.and(entries.get("spring.data.mongodb.password"));
    let auth = userinfo(user, password);
    Some(format!("mongodb://{auth}{host}:{port}/{db}?ssl={ssl}"))
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

/// Percent-decodes a URL component such as the user name or password.
///
/// `url::Url::username()` / `password()` return the encoded form, e.g. `p%40ss` for `p@ss`.
/// Falls back to the raw text when the decoded bytes are not valid UTF-8.
fn url_decode(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| text.to_string())
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
            .extend(["-u".to_string(), url_decode(parsed_url.username())]);
    } else if let Some(db_user) = db_user {
        inv.args.extend(["-u".to_string(), db_user]);
    }
    if let Some(password) = parsed_url.password().map(url_decode).or(db_password) {
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
            .extend(["-U".to_string(), url_decode(parsed_url.username())]);
    } else if let Some(db_user) = db_user {
        inv.args.extend(["-U".to_string(), db_user]);
    }
    if let Some(password) = parsed_url.password().map(url_decode).or(db_password) {
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
    let username = redis_user.unwrap_or_else(|| url_decode(parsed_url.username()));
    let password =
        redis_password.unwrap_or_else(|| url_decode(parsed_url.password().unwrap_or_default()));
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
        if mongodb_url.starts_with("mongodb:") || mongodb_url.starts_with("mongodb+srv:") {
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
        if self.variables.is_empty() {
            return None;
        }
        let child_type = self.child_type.as_deref();
        if self.obj_type == "secret" {
            let Some(child_type) = child_type else {
                eprintln!(
                    "{} DUCKDB__{}__TYPE is missing, secret '{}' skipped.",
                    "✖ ".red(),
                    self.name.to_uppercase(),
                    self.name
                );
                return None;
            };
            let variables = self
                .variables
                .iter()
                .map(|(k, v)| format!("{k} {}", sql_quote(v)))
                .collect::<Vec<String>>()
                .join(", ");
            return Some(format!(
                "CREATE SECRET {} ( TYPE {child_type}, {variables});",
                self.name
            ));
        } else if self.obj_type == "attach" {
            let mut db_variables = self.variables.clone();
            let db_url = db_variables.remove("URL").unwrap_or_default();
            let mut options: Vec<String> = Vec::new();
            if let Some(child_type) = child_type {
                options.push(format!("TYPE {child_type}"));
            }
            options.extend(db_variables.iter().map(|(k, v)| {
                if v == "true" || v == "false" {
                    format!("{k} {v}")
                } else {
                    format!("{k} {}", sql_quote(v))
                }
            }));
            let options = if options.is_empty() {
                String::new()
            } else {
                format!(" ({})", options.join(", "))
            };
            return Some(format!(
                "ATTACH {} AS {}{options};",
                sql_quote(db_url.trim_matches('\'')),
                self.name
            ));
        }
        None
    }
}

/// Quotes a value as a SQL string literal, escaping embedded single quotes.
fn sql_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// `DUCKDB__PARQUET__<NAME>=<key>` → `PRAGMA add_parquet_key('<name>', '<key>');`
fn parquet_key_sql(key_name: &str, aes_key: &str) -> String {
    format!(
        "PRAGMA add_parquet_key({}, {});",
        sql_quote(key_name),
        sql_quote(aes_key)
    )
}

/// `DUCKDB__ENCRYPTED__<NAME>=<aes_key>@<db_path>` →
/// `ATTACH '<db_path>' AS <name> (ENCRYPTION_KEY '<aes_key>');`
fn encrypted_attach_sql(db_name: &str, value: &str) -> Option<String> {
    let (aes_key, db_path) = value.split_once('@')?;
    if aes_key.is_empty() || db_path.is_empty() {
        return None;
    }
    Some(format!(
        "ATTACH {} AS {db_name} (ENCRYPTION_KEY {});",
        sql_quote(db_path),
        sql_quote(aes_key)
    ))
}

/// `DUCKDB__DUCKLAKE__<NAME>=<catalog_url> [(<options>)]` →
/// `ATTACH '<catalog_url>' AS <name> [(<options>)];`
///
/// The options are raw SQL (e.g. `DATA_PATH 's3://bucket/'`) and are passed through unchanged.
fn ducklake_attach_sql(db_name: &str, value: &str) -> Option<String> {
    let value = value.trim();
    let (catalog_db_url, options) = match value.find('(') {
        Some(pos) => {
            let options = value[pos + 1..].trim_end().strip_suffix(')')?.trim();
            (value[..pos].trim(), options)
        }
        None => (value, ""),
    };
    let catalog_db_url = catalog_db_url.trim_matches('\'');
    if catalog_db_url.is_empty() {
        return None;
    }
    let options = if options.is_empty() {
        String::new()
    } else {
        format!(" ({options})")
    };
    Some(format!(
        "ATTACH {} AS {db_name}{options};",
        sql_quote(catalog_db_url)
    ))
}

fn get_duckdb_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    let mut obj_names: Vec<String> = Vec::new();
    let mut misc_sql_sentences: Vec<String> = Vec::new();
    let mut encrypt_db_included = false;
    for (key, value) in env::vars() {
        if let Some(parquet_key_name) = key.strip_prefix("DUCKDB__PARQUET__") {
            // https://duckdb.org/docs/stable/data/parquet/encryption
            misc_sql_sentences.push(parquet_key_sql(&parquet_key_name.to_lowercase(), &value));
        } else if let Some(db_name) = key.strip_prefix("DUCKDB__ENCRYPTED__") {
            // https://duckdb.org/docs/stable/sql/statements/attach#database-encryption
            if let Some(sql) = encrypted_attach_sql(&db_name.to_lowercase(), &value) {
                misc_sql_sentences.push(sql);
                encrypt_db_included = true;
            } else {
                eprintln!(
                    "{} {key} should be in format '<aes_key>@<db_path>', skipped.",
                    "✖ ".red()
                );
            }
        } else if let Some(db_name) = key.strip_prefix("DUCKDB__DUCKLAKE__") {
            // https://ducklake.select/docs/stable/duckdb/usage/connecting
            if let Some(sql) = ducklake_attach_sql(&db_name.to_lowercase(), &value) {
                misc_sql_sentences.push(sql);
            } else {
                eprintln!(
                    "{} {key} should be in format '<catalog_url> (<options>)', skipped.",
                    "✖ ".red()
                );
            }
        } else if key.starts_with("DUCKDB__")
            && let Some(secret_name) = key.split("__").nth(1)
        {
            let name = secret_name.to_string();
            if !obj_names.contains(&name) {
                obj_names.push(name);
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
    for secret_name in obj_names {
        if let Some(duck_obj) = DuckSecret::from_env(secret_name)
            && let Some(sql) = duck_obj.to_sql()
        {
            if duck_obj.obj_type == "secret" {
                println!("{} secret of '{}' created.", "✔ ".green(), duck_obj.name);
            } else if duck_obj.obj_type == "attach" {
                println!("{} database of '{}' attached.", "✔ ".green(), duck_obj.name);
            }
            args.push("--cmd".to_string());
            args.push(sql);
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

    fn duck_obj(obj_type: &str, child_type: Option<&str>, vars: &[(&str, &str)]) -> DuckSecret {
        DuckSecret {
            name: "demo".to_string(),
            obj_type: obj_type.to_string(),
            child_type: child_type.map(str::to_string),
            variables: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn test_duckdb_ducklake_sql() {
        assert_eq!(
            ducklake_attach_sql("lake", "ducklake:metadata.ducklake (DATA_PATH 'data/')").unwrap(),
            "ATTACH 'ducklake:metadata.ducklake' AS lake (DATA_PATH 'data/');"
        );
        assert_eq!(
            ducklake_attach_sql("lake", "'ducklake:a.ducklake'").unwrap(),
            "ATTACH 'ducklake:a.ducklake' AS lake;"
        );
        assert_eq!(
            ducklake_attach_sql("lake", "ducklake:o'k.ducklake").unwrap(),
            "ATTACH 'ducklake:o''k.ducklake' AS lake;"
        );
        assert!(ducklake_attach_sql("lake", "ducklake:x (DATA_PATH 'a'").is_none());
        assert!(ducklake_attach_sql("lake", "(DATA_PATH 'a')").is_none());
    }

    #[test]
    fn test_duckdb_encrypted_sql() {
        assert_eq!(
            encrypted_attach_sql("enc", "k'ey@my db.duckdb").unwrap(),
            "ATTACH 'my db.duckdb' AS enc (ENCRYPTION_KEY 'k''ey');"
        );
        assert!(encrypted_attach_sql("enc", "no-at-sign").is_none());
        assert!(encrypted_attach_sql("enc", "@path.db").is_none());
        assert!(encrypted_attach_sql("enc", "key@").is_none());
    }

    #[test]
    fn test_duckdb_parquet_sql() {
        assert_eq!(
            parquet_key_sql("k1", "ab'c"),
            "PRAGMA add_parquet_key('k1', 'ab''c');"
        );
    }

    #[test]
    fn test_duckdb_secret_sql() {
        // missing __TYPE: skipped instead of panicking
        assert!(
            duck_obj("secret", None, &[("BEARER_TOKEN", "x")])
                .to_sql()
                .is_none()
        );
        assert_eq!(
            duck_obj("secret", Some("http"), &[("BEARER_TOKEN", "a'b")])
                .to_sql()
                .unwrap(),
            "CREATE SECRET demo ( TYPE http, BEARER_TOKEN 'a''b');"
        );
    }

    #[test]
    fn test_duckdb_attach_sql() {
        assert_eq!(
            duck_obj("attach", Some("duckdb"), &[("URL", "o'k.db")])
                .to_sql()
                .unwrap(),
            "ATTACH 'o''k.db' AS demo (TYPE duckdb);"
        );
        assert_eq!(
            duck_obj(
                "attach",
                None,
                &[("URL", "a.db"), ("ENCRYPTION_KEY", "p'w")]
            )
            .to_sql()
            .unwrap(),
            "ATTACH 'a.db' AS demo (ENCRYPTION_KEY 'p''w');"
        );
        assert_eq!(
            duck_obj(
                "attach",
                Some("duckdb"),
                &[("URL", "'a.db'"), ("READ_ONLY", "true")]
            )
            .to_sql()
            .unwrap(),
            "ATTACH 'a.db' AS demo (TYPE duckdb, READ_ONLY true);"
        );
    }

    #[test]
    fn test_is_shim_command() {
        for name in [
            "dotenvx",
            "dotenvx.exe",
            "dotenvx-aarch64",
            "dotenvx_v1.exe",
            "DotEnvX",
        ] {
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
        assert_eq!(
            found,
            Some(real.join("mysql").to_string_lossy().to_string())
        );
        // only dotenvx entries -> not found
        let paths = std::env::join_paths([&a, &b, &c, &d]).unwrap();
        assert_eq!(
            find_command_path_in("mysql", &paths, root, Some(&dotenvx)),
            None
        );
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
    fn test_url_credentials_are_percent_decoded() {
        let pwd = |inv: &ShimInvocation| inv.envs[0].1.clone();
        let inv = mysql_invocation("mysql://us%40er:p%40ss%3Aw%2F%23%25@db/app", None, None);
        assert_eq!(pwd(&inv), "p@ss:w/#%");
        assert!(inv.args.contains(&"us@er".to_string()));
        let inv = psql_invocation("postgres://us%40er:p%40ss@db/app", None, None);
        assert_eq!(pwd(&inv), "p@ss");
        assert!(inv.args.contains(&"us@er".to_string()));
        let inv = redis_invocation("redis://us%40er:p%40ss@cache", None, None);
        assert_eq!(pwd(&inv), "p@ss");
        assert!(inv.args.contains(&"us@er".to_string()));
        // invalid UTF-8 after decoding keeps the raw text
        let inv = redis_invocation("redis://:p%FFss@cache", None, None);
        assert_eq!(pwd(&inv), "p%FFss");
    }

    fn entries(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_spring_redis_url() {
        assert_eq!(spring_redis_url(&entries(&[])), None);
        assert_eq!(
            spring_redis_url(&entries(&[("spring.data.redis.url", "redis://h:1/2")])),
            Some("redis://h:1/2".to_string())
        );
        assert_eq!(
            spring_redis_url(&entries(&[("spring.data.redis.host", "localhost")])),
            Some("redis://localhost:6379/0".to_string())
        );
        let url = spring_redis_url(&entries(&[
            ("spring.data.redis.host", "cache"),
            ("spring.data.redis.port", "6380"),
            ("spring.data.redis.database", "3"),
            ("spring.data.redis.ssl.enabled", "true"),
            ("spring.data.redis.username", "app"),
            ("spring.data.redis.password", "p@ss:w/rd#%"),
        ]))
        .unwrap();
        assert_eq!(url, "rediss://app:p%40ss%3Aw%2Frd%23%25@cache:6380/3");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(url_decode(parsed.password().unwrap()), "p@ss:w/rd#%");
        assert_eq!(parsed.host_str(), Some("cache"));
        // password without a user name
        assert_eq!(
            spring_redis_url(&entries(&[
                ("spring.data.redis.host", "localhost"),
                ("spring.data.redis.password", "secret"),
            ])),
            Some("redis://:secret@localhost:6379/0".to_string())
        );
    }

    #[test]
    fn test_spring_mongodb_url() {
        assert_eq!(spring_mongodb_url(&entries(&[])), None);
        assert_eq!(
            spring_mongodb_url(&entries(&[(
                "spring.data.mongodb.uri",
                "mongodb+srv://u:p@cluster0.example.net/db"
            )])),
            Some("mongodb+srv://u:p@cluster0.example.net/db".to_string())
        );
        let url = spring_mongodb_url(&entries(&[
            ("spring.data.mongodb.host", "mongo"),
            ("spring.data.mongodb.database", "app"),
            ("spring.data.mongodb.username", "admin@corp"),
            ("spring.data.mongodb.password", "p@ss/word"),
        ]))
        .unwrap();
        assert_eq!(
            url,
            "mongodb://admin%40corp:p%40ss%2Fword@mongo:27017/app?ssl=false"
        );
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(url_decode(parsed.username()), "admin@corp");
        assert_eq!(url_decode(parsed.password().unwrap()), "p@ss/word");
        assert_eq!(
            spring_mongodb_url(&entries(&[
                ("spring.data.mongodb.host", "mongo"),
                ("spring.data.mongodb.password", "secret"),
            ])),
            Some("mongodb://mongo:27017/test?ssl=false".to_string())
        );
    }

    #[test]
    fn test_url_encode_userinfo_round_trip() {
        for text in ["p@ss", "a:b/c?d#e%f", "中文 密码", "-._~"] {
            assert_eq!(url_decode(&url_encode_userinfo(text)), text);
        }
        assert_eq!(url_encode_userinfo("-._~"), "-._~");
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
