use std::env;

pub fn get_profile_name_from_env() -> Option<String> {
    let env_vars = ["NODE_ENV", "RUN_ENV", "APP_ENV", "SPRING_PROFILES_ACTIVE"];
    for var in env_vars.iter() {
        if let Ok(value) = env::var(var) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub fn get_profile_name_from_file(env_file_name: &str) -> Option<String> {
    if env_file_name.starts_with(".env.") {
        let profile_name = env_file_name.replace(".env.", "");
        return Some(profile_name);
    } else if env_file_name.ends_with(".properties") && env_file_name.contains('_') {
        return env_file_name
            .replace(".properties", "")
            .rsplit('_')
            .next()
            .map(|x| x.to_string());
    }
    None
}
