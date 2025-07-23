use std::env;

pub fn get_profile_name() -> Option<String> {
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
