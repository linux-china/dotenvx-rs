use aes_gcm::aead::OsRng;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::SaltString;
use argon2::{self, Argon2, PasswordHasher};
use base64::engine::general_purpose;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use colored::Colorize;
use dotenvx_rs::dotenvx::get_private_key;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use libsecp256k1::{sign, Message};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use totp_rs::TOTP;

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

/// trim the message and sign it using the private key and return the signature in base64 format
pub fn sign_message(private_key: &str, message: &str) -> anyhow::Result<String> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    // Step 2: Sign the message hash with the private key
    let sk_bytes = hex::decode(private_key)?;
    if let Ok(sk) = SecretKey::parse_slice(&sk_bytes) {
        let signature = sign(&msg, &sk).0;
        Ok(general_purpose::STANDARD.encode(signature.serialize()))
    } else {
        Err(anyhow::anyhow!("Invalid private key format"))
    }
}

/// trim the message and sign it using the private key and return the signature in bytes format
pub fn sign_message_bytes(private_key: &str, message: &str) -> anyhow::Result<Vec<u8>> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    // Step 2: Sign the message hash with the private key
    let sk_bytes = hex::decode(private_key)?;
    if let Ok(sk) = SecretKey::parse_slice(&sk_bytes) {
        let signature = sign(&msg, &sk).0;
        Ok(signature.serialize().to_vec())
    } else {
        Err(anyhow::anyhow!("Invalid private key format"))
    }
}

/// trim the message and verify the signature using the public key
pub fn verify_signature(public_key: &str, message: &str, signature: &str) -> anyhow::Result<bool> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    // Step 2: Verify the signature with the public key
    let pk_bytes = hex::decode(public_key)?;
    if let Ok(pk) = PublicKey::parse_slice(&pk_bytes, None) {
        let signature_bytes = general_purpose::STANDARD.decode(signature)?;
        let signature = libsecp256k1::Signature::parse_standard_slice(&signature_bytes).unwrap();
        let result = libsecp256k1::verify(&msg, &signature, &pk);
        if result {
            Ok(true)
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    } else {
        Err(anyhow::anyhow!("Invalid public key format"))
    }
}

/// generate a JWT token using the private key and claims, and algorithm ES256K(secp256k1)
pub fn generate_jwt_token(
    private_key_hext: &str,
    claims: serde_json::Value,
) -> anyhow::Result<String> {
    let header_obj = json!({"typ": "JWT","alg": "ES256K"});
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header_obj)?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?);
    let message = format!("{header}.{payload}");
    let signature_bytes = sign_message_bytes(private_key_hext, &message)?;
    let signature = URL_SAFE_NO_PAD.encode(signature_bytes.as_slice());
    Ok(format!("{header}.{payload}.{signature}"))
}

//============= aes_gcm =======
pub fn encrypt_file<P: AsRef<Path>>(
    input_file: P,
    output_file: P,
    password: &str,
) -> anyhow::Result<()> {
    let plain_bytes = std::fs::read(input_file)?;
    // password hashing with Argon2
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
    let hash = password_hash.hash.unwrap();

    // Initialize AES-GCM with the derived key
    let aes_key = Key::<Aes256Gcm>::from_slice(hash.as_bytes()); // Use the first 32 bytes of the hash
    let cipher = Aes256Gcm::new(aes_key);

    // Generate a random nonce
    let random_nonce = rand::random::<[u8; 12]>();
    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&random_nonce), plain_bytes.as_ref())
        .expect("encryption failure!");

    // // Write the salt, nonce, and ciphertext to the output file
    let mut output = File::create(output_file)?;
    let mut salt_bytes: [u8; 16] = [0; 16];
    salt.decode_b64(&mut salt_bytes).unwrap();
    output.write_all(&salt_bytes)?; // First 16 bytes: salt
    output.write_all(&random_nonce)?; // Next 12 bytes: nonce
    output.write_all(&ciphertext)?; // Remaining bytes: ciphertext
    Ok(())
}

pub fn decrypt_file<P: AsRef<Path>>(
    encrypted_file: P,
    output_file: P,
    password: &str,
) -> anyhow::Result<()> {
    // Read the encrypted file
    let encrypted_file_content = fs::read(encrypted_file)?;

    // Extract the salt, nonce, and ciphertext
    let salt_bytes = &encrypted_file_content[0..16]; // First 16 bytes: salt
    let salt = SaltString::encode_b64(salt_bytes).unwrap();
    let nonce_bytes = &encrypted_file_content[16..28]; // Next 12 bytes: nonce
    let ciphertext = &encrypted_file_content[28..]; // Remaining bytes: ciphertext

    // password hashing with Argon2
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
    let hash = password_hash.hash.unwrap();

    // Initialize AES-GCM with the derived key
    let aes_key = Key::<Aes256Gcm>::from_slice(hash.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);

    // Decrypt the ciphertext
    let plain_bytes = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .expect("decryption failure!");

    // Write the decrypted bytes to the output file
    fs::write(output_file, plain_bytes)?;
    Ok(())
}

fn generate_totp_password(totp_url: &str) -> anyhow::Result<String> {
    let totp = TOTP::from_url(totp_url)?;
    totp.generate_current()
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

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

    #[test]
    fn test_jwt_generate() {
        let private_key = "9e70188d351c25d0714929205df9b8f4564b6b859966bdae7aef7f752a749d8b";
        let claims = json!({
            "sub": "example-user",
            "exp": 1735689600, // Expiration time (e.g., 2025-01-01T00:00:00Z)
            "iat": 1622505600, // Issued at time (e.g., 2021-06-01T00:00:00Z)
            "iss": "example-issuer"
        });
        let jwt_token = generate_jwt_token(private_key, claims).unwrap();
        println!("JWT: {jwt_token}");
    }

    #[test]
    fn test_encrypt_file() -> TestResult {
        // Input file and password
        let input_file = "tests/example.txt";
        let output_file = "tests/example.txt.aes";
        let password = "your_secure_password";
        // Encrypt the file
        encrypt_file(input_file, output_file, password).unwrap();
        Ok(())
    }

    #[test]
    fn test_decrypt_file() -> TestResult {
        // Input file and password
        let encrypted_file = "tests/example.txt.aes";
        let output_file = "tests/example.txt";
        let password = "your_secure_password";
        // Encrypt the file
        decrypt_file(encrypted_file, output_file, password).unwrap();
        Ok(())
    }
}
