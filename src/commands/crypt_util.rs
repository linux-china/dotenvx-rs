use base64::engine::general_purpose;
use base64::Engine;
use colored::Colorize;
use dotenvx_rs::dotenvx::get_private_key;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use libsecp256k1::{sign, Message};
use sha2::{Digest, Sha256};

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

/// trim the message and sign it using the private key
pub fn sign_message(
    private_key: &str,
    message: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    // Step 2: Sign the message hash with the private key
    let sk_bytes = hex::decode(private_key).unwrap();
    let sk = SecretKey::parse_slice(&sk_bytes).unwrap();
    let signature = sign(&msg, &sk).0;
    let signature_text = general_purpose::STANDARD.encode(signature.serialize());
    Ok(signature_text)
}

/// trim the message and verify the signature using the public key
pub fn verify_signature(
    public_key: &str,
    message: &str,
    signature: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    // Step 2: Verify the signature with the public key
    let pk_bytes = hex::decode(public_key).unwrap();
    let pk = PublicKey::parse_slice(&pk_bytes, None).unwrap();
    let signature_bytes = general_purpose::STANDARD.decode(signature).unwrap();
    let signature = libsecp256k1::Signature::parse_standard_slice(&signature_bytes).unwrap();
    Ok(libsecp256k1::verify(&msg, &signature, &pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_and_verify() {
        let public_key = "02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0";
        let private_key = "9e70188d351c25d0714929205df9b8f4564b6b859966bdae7aef7f752a749d8b";
        let message = "Hello, secp256k1!";
        // Sign the message
        let signature = sign_message(private_key, message).unwrap();
        println!("Signature: {signature}");
        let verify_result = verify_signature(public_key, message, &signature).unwrap();
        assert!(verify_result, "Signature verification failed");
    }
}
