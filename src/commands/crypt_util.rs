use base64::engine::general_purpose;
use base64::Engine;
use colored::Colorize;
use dotenvx_rs::dotenvx::get_private_key;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};

pub struct EcKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl EcKeyPair {
    pub fn generate() -> Self {
        let (sk, pk) = generate_keypair();
        EcKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn from_secret_key(sk_hex: &str) -> Self {
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk = SecretKey::parse_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);
        EcKeyPair {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn get_pk_hex(&self) -> String {
        let pk_compressed_bytes = self.public_key.serialize_compressed();
        hex::encode(pk_compressed_bytes)
    }

    pub fn get_sk_hex(&self) -> String {
        let sk_bytes = self.secret_key.serialize();
        hex::encode(sk_bytes)
    }
}

pub fn encrypt_env_item(
    public_key: &str,
    value_plain: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let pk_bytes = hex::decode(public_key).unwrap();
    let encrypted_bytes = ecies::encrypt(&pk_bytes, value_plain.as_bytes()).unwrap();
    let base64_text = general_purpose::STANDARD.encode(encrypted_bytes);
    Ok(format!("encrypted:{base64_text}"))
}

pub fn decrypt_env_item(
    private_key: &str,
    encrypted_text: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = if encrypted_text.starts_with("encrypted:") {
        general_purpose::STANDARD
            .decode(encrypted_text.strip_prefix("encrypted:").unwrap())
            .unwrap()
    } else {
        general_purpose::STANDARD.decode(encrypted_text).unwrap()
    };
    let sk = hex::decode(private_key).unwrap();
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes).unwrap();
    Ok(String::from_utf8(decrypted_bytes)?)
}

pub fn decrypt_value(profile: &Option<String>, encrypted_value: &str) {
    if let Ok(private_key) = get_private_key(profile) {
        if let Ok(plain_text) = decrypt_env_item(&private_key, encrypted_value) {
            println!("{plain_text}");
        } else {
            eprintln!(
                "{}",
                "Failed to decrypt the value, please check the private key and profile.".red()
            );
        }
    } else {
        eprintln!("{}",
                  "Private key not found, please check the DOTENV_PRIVATE_KEY environment variable or '.env.key' file.".red()
        );
    }
}
