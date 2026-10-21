use crate::commands::crypt_util::{generate_jwt_token, sha256};
use crate::commands::{find_all_keys, http_agent};
use crate::commands::model::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfResponse {
    pub status: u32,
    pub data: Option<SelfInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfInfo {
    pub id: u32,
    pub nick: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub status: u32,
    pub data: Option<RegistrationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    pub nick: String,
    pub password: String,
    #[serde(rename = "totpUrl")]
    pub totp_url: String,
}

pub fn fetch_self_info(private_key: &str) -> anyhow::Result<SelfInfo> {
    let jwt_token = generate_request_token(private_key)?;
    let mut response = http_agent()
        .get("https://dotenvx-api.microservices.club/api/v1/users/me")
        .header("Authorization", format!("Bearer {jwt_token}"))
        .call()?;
    if response.status() == 200 {
        let self_response: SelfResponse = response.body_mut().read_json()?;
        Ok(self_response.data.unwrap())
    } else {
        Err(anyhow::anyhow!(
            "status: {}, msg: {}",
            response.status(),
            response.body_mut().read_to_string()?,
        ))
    }
}

pub fn register(
    public_key: &str,
    private_key_sha256: &str,
    nick: &str,
    email: &str,
    phone: &str,
) -> anyhow::Result<RegistrationResult> {
    let mut response = http_agent()
        .post("https://dotenvx-api.microservices.club/registration")
        .send_json(json!({
            "nick": nick,
            "email": email,
            "phone": phone,
            "publicKey": public_key,
            "privateKeySha256": private_key_sha256,
        }))?;
    if response.status() == 200 {
        let self_response: RegistrationResponse = response.body_mut().read_json()?;
        Ok(self_response.data.unwrap())
    } else {
        Err(anyhow::anyhow!(
            "status: {}, msg: {}",
            response.status(),
            response.body_mut().read_to_string()?,
        ))
    }
}

fn generate_request_token(private_key: &str) -> anyhow::Result<String> {
    use chrono::Utc;
    let now = Utc::now().timestamp();
    let bytes = hex::decode(private_key)?;
    let claims = json!({
        "kid": sha256(&bytes),
        "exp": now + 300, // 5 minutes later
        "iat": now,
        "iss": "dotenvx"
    });
    generate_jwt_token(private_key, claims)
}

pub fn find_dotenvx_cloud_key_pair() -> Option<KeyPair> {
    let pairs = find_all_keys();
    for (_, pair) in pairs {
        if let Some(group) = &pair.group
            && group == "dotenvx"
            && let Some(name) = &pair.name
            && name == "dotenvx-cloud"
            && let Some(profile_name) = &pair.profile
            && profile_name == "g_dotenvx"
        {
            return Some(pair.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_self_info() {
        let key_pair = find_dotenvx_cloud_key_pair().unwrap();
        let self_info = fetch_self_info(&key_pair.private_key).unwrap();
        println!("Self info: {self_info:?}");
    }

    #[test]
    fn test_jwt_token() {
        let key_pair = find_dotenvx_cloud_key_pair().unwrap();
        let jwt_token = generate_request_token(&key_pair.private_key).unwrap();
        println!("JWT token: {jwt_token}");
    }
}
