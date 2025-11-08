use crate::commands::decrypt::decrypt_env_entries;
use crate::commands::framework::detect_framework;
use colored::Colorize;
use dotenvx_rs::common::get_profile_name_from_env;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn is_shim_command(command_name: &str) -> bool {
    !(command_name == "dotenvx" || command_name == "dotenvx.exe")
}

pub fn run_shim(command_name: &str, command_args: &[String]) -> i32 {
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
        if command_name == "mysql" || command_name == "mysql.exe" {
            new_command_args.extend(get_mysql_args());
        } else if command_name == "psql" || command_name == "psql.exe" {
            new_command_args.extend(get_psql_args());
        } else if command_name == "redis-cli" || command_name == "redis-cli.exe" {
            new_command_args.extend(get_redis_args());
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
            .args(&new_command_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .expect("DOTENV-CMD-500: failed to run command");
        let status = child.wait().expect("DOTENV-CMD-500: failed to run command");
        if let Some(code) = status.code() {
            code
        } else {
            // On Unix, process was terminated by signal
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    std::process::exit(128 + signal);
                }
            }
            1
        }
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

fn get_mysql_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    let mut mysql_url =
        env::var("MYSQL_URL").unwrap_or(env::var("DATABASE_URL").unwrap_or_default());
    if !mysql_url.is_empty() {
        if mysql_url.starts_with("jdbc:") {
            mysql_url = mysql_url.trim_start_matches("jdbc:").to_string();
        }
        if mysql_url.starts_with("mysql:") || mysql_url.starts_with("mariadb:") {
            if let Ok(parsed_url) = url::Url::parse(&mysql_url) {
                if let Some(host) = parsed_url.host_str() {
                    args.push("-h".to_string());
                    args.push(host.to_string());
                }
                if let Some(port) = parsed_url.port() {
                    args.push("-P".to_string());
                    args.push(port.to_string());
                }
                if !parsed_url.username().is_empty() {
                    args.push("-u".to_string());
                    args.push(parsed_url.username().to_string());
                } else if let Ok(db_user) = env::var("DB_USER") {
                    args.push("-u".to_string());
                    args.push(db_user);
                }
                if let Some(password) = parsed_url.password() {
                    args.push(format!("--password={password}"));
                } else if let Ok(db_password) = env::var("DB_PASSWORD") {
                    args.push(format!("--password={db_password}"));
                }
                let db_name = parsed_url.path().trim_start_matches('/');
                if !db_name.is_empty() {
                    args.push(db_name.to_string());
                }
            }
        }
    }
    args
}

fn get_psql_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    let mut pg_url =
        env::var("POSTGRES_URL").unwrap_or(env::var("DATABASE_URL").unwrap_or_default());
    if !pg_url.is_empty() {
        if pg_url.starts_with("jdbc:") {
            pg_url = pg_url.trim_start_matches("jdbc:").to_string();
        }
        if pg_url.starts_with("postgres:") || pg_url.starts_with("postgresql:") {
            if let Ok(parsed_url) = url::Url::parse(&pg_url) {
                if let Some(host) = parsed_url.host_str() {
                    args.push("-h".to_string());
                    args.push(host.to_string());
                }
                if let Some(port) = parsed_url.port() {
                    args.push("-p".to_string());
                    args.push(port.to_string());
                }
                if !parsed_url.username().is_empty() {
                    args.push("-U".to_string());
                    args.push(parsed_url.username().to_string());
                } else if let Ok(db_user) = env::var("DB_USER") {
                    args.push("-U".to_string());
                    args.push(db_user);
                }
                if let Some(password) = parsed_url.password() {
                    // args.push(format!("--password={password}"));
                    unsafe {
                        env::set_var("PGPASSWORD", password);
                    }
                } else if let Ok(db_password) = env::var("DB_PASSWORD") {
                    // args.push(format!("--password={db_password}"));
                    unsafe {
                        env::set_var("PGPASSWORD", password);
                    }
                }
                let db_name = parsed_url.path().trim_start_matches('/');
                if !db_name.is_empty() {
                    args.push(db_name.to_string());
                }
            }
        }
    }
    args
}

fn get_redis_args() -> Vec<String> {
    let mut args: Vec<String> = vec![];
    if let Ok(redis_url) = env::var("REDIS_URL") {
        if redis_url.starts_with("redis:") || redis_url.starts_with("rediss:") {
            if let Ok(parsed_url) = url::Url::parse(&redis_url) {
                if let Some(host) = parsed_url.host_str() {
                    args.push("-h".to_string());
                    args.push(host.to_string());
                }
                if let Some(port) = parsed_url.port() {
                    args.push("-p".to_string());
                    args.push(port.to_string());
                }
                let mut username = parsed_url.username().to_string();
                let mut password = parsed_url.password().unwrap_or_default().to_string();
                if let Ok(redis_password) = env::var("REDIS_PASSWORD") {
                    password = redis_password;
                }
                if let Ok(redis_user) = env::var("REDIS_USER") {
                    username = redis_user;
                }
                if !username.is_empty() && !password.is_empty() {
                    args.push("-u".to_string());
                    args.push(username);
                    args.push("-a".to_string());
                    args.push(password);
                } else if !username.is_empty() && password.is_empty() {
                    args.push("-u".to_string());
                    args.push(username);
                } else if username.is_empty() && !password.is_empty() {
                    args.push("-a".to_string());
                    args.push(password);
                }
                let db_index = parsed_url.path().trim_start_matches('/').to_string();
                if !db_index.is_empty() {
                    args.push("-n".to_string());
                    args.push(db_index);
                }
            }
        }
    }
    args
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
    for (key, value) in env::vars() {
        if key.starts_with("DUCKDB__") {
            if let Some(secret_name) = key.split("__").nth(1) {
                let name = secret_name.to_string();
                if !obj_names.contains(&name) {
                    obj_names.push(name);
                }
            }
        }
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
        let path = find_command_path("lua");
        println!("Found command path: {:?}", path);
        assert!(path.is_some());
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
