use std::env;
use std::process::{Command, Stdio};

pub fn is_shim_command(command_name: &str) -> bool {
    !(command_name == "dotenvx" || command_name == "dotenvx.exe")
}

pub fn run_shim(command_name: &str, command_args: &[String]) -> i32 {
    if let Some(command_path) = find_command_path(command_name) {
        let _ = dotenvx_rs::dotenv().is_ok();
        let mut new_command_args: Vec<String> = vec![];
        if command_name == "mysql" || command_name == "mysql.exe" {
            new_command_args.extend(get_mysql_args());
        } else if command_name == "psql" || command_name == "psql.exe" {
            new_command_args.extend(get_psql_args());
        } else if command_name == "redis-cli" || command_name == "redis-cli.exe" {
            new_command_args.extend(get_redis_args());
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
                }
                if let Some(password) = parsed_url.password() {
                    args.push(format!("--password={password}"));
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
                }
                if let Some(password) = parsed_url.password() {
                    args.push(format!("--password={password}"));
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
    let redis_url = env::var("REDIS_URL").unwrap_or_default();
    if !redis_url.is_empty() {
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
                if let Some(password) = parsed_url.password() {
                    args.push("-a".to_string());
                    args.push(password.to_string());
                } else if !parsed_url.username().is_empty() && parsed_url.password().is_none() {
                    args.push("-a".to_string());
                    args.push(parsed_url.username().to_string());
                } else {
                    args.push("--user".to_string());
                    args.push("".to_string());
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
}
