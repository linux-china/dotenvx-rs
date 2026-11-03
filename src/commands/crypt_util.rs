use crate::commands::trim_private_key;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::try_generate_salt;
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use colored::Colorize;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecretKey};
use k256::ecdsa::{
    Signature as EcdsaSignature, SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use totp_rs::Totp;

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

    /// Parse a private key hex, tolerating the `{...}` suffix and a prefix before the last 64 hex chars.
    /// Returns an error instead of panicking on an invalid key.
    pub fn from_secret_key(sk_hex: &str) -> anyhow::Result<Self> {
        let trimmed = trim_private_key(sk_hex.trim().to_string());
        let sk_bytes = hex::decode(check_sk_hex(&trimmed))
            .map_err(|e| anyhow::anyhow!("Invalid private key hex: {e}"))?;
        let sk = SecretKey::parse_slice(&sk_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid private key"))?;
        let pk = PublicKey::from_secret_key(&sk);
        Ok(EcKeyPair {
            public_key: pk,
            secret_key: sk,
        })
    }

    pub fn from_input(sk_hex: &str) -> anyhow::Result<Self> {
        let sk_bytes = hex::decode(trim_private_key(sk_hex.to_string()))?;
        let sk =
            SecretKey::parse_slice(&sk_bytes).map_err(|_| anyhow::anyhow!("Invalid secret key"))?;
        let pk = PublicKey::from_secret_key(&sk);
        Ok(EcKeyPair {
            public_key: pk,
            secret_key: sk,
        })
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

pub fn check_sk_hex(sk_hex: &str) -> &str {
    let key_len = sk_hex.len();
    if key_len > 64 {
        &sk_hex[(key_len - 64)..]
    } else {
        sk_hex
    }
}

pub fn encrypt_env_item(
    public_key: &str,
    value_plain: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let pk_bytes = hex::decode(public_key)?;
    let encrypted_bytes = ecies::encrypt(&pk_bytes, value_plain.as_bytes())?;
    let base64_text = Base64::encode_string(&encrypted_bytes);
    Ok(format!("encrypted:{base64_text}"))
}

pub fn decrypt_env_item(
    private_key: &str,
    encrypted_text: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = if let Some(stripped_value) = encrypted_text.strip_prefix("encrypted:") {
        dotenvx_rs::common::decode_base64_lenient(stripped_value)?
    } else {
        dotenvx_rs::common::decode_base64_lenient(encrypted_text)?
    };
    let sk = hex::decode(check_sk_hex(private_key))?;
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes)?;
    Ok(String::from_utf8(decrypted_bytes)?)
}

pub fn decrypt_value(profile: &Option<String>, encrypted_value: &str) {
    // same lookup as the other commands: verified against the profile's declared public key (review #16)
    if let Ok(private_key) = crate::commands::get_private_key(profile) {
        if let Ok(plain_text) = decrypt_env_item(check_sk_hex(&private_key), encrypted_value) {
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

pub fn sha256(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(result)
}

/// trim the message and sign it using the private key and return the signature in base64 format
pub fn sign_message(private_key: &str, message: &str) -> anyhow::Result<String> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    // Step 2: Sign the message hash with the private key
    let sk_bytes = hex::decode(check_sk_hex(private_key))?;
    let signing_key = SigningKey::from_slice(&sk_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid private key format"))?;
    let (signature, _) = signing_key.sign_prehash_recoverable(&message_hash);
    Ok(Base64::encode_string(&signature.to_bytes()))
}

/// trim the message and sign it using the private key and return the signature in bytes format
pub fn sign_message_bytes(private_key: &str, message: &str) -> anyhow::Result<Vec<u8>> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    // Step 2: Sign the message hash with the private key
    let sk_bytes = hex::decode(check_sk_hex(private_key))?;
    let signing_key = SigningKey::from_slice(&sk_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid private key format"))?;
    let (signature, _) = signing_key.sign_prehash_recoverable(&message_hash);
    Ok(signature.to_bytes().to_vec())
}

/// trim the message and verify the signature using the public key
pub fn verify_signature(public_key: &str, message: &str, signature: &str) -> anyhow::Result<bool> {
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message.trim());
    let message_hash = hasher.finalize();
    // Step 2: Verify the signature with the public key
    let pk_bytes = hex::decode(public_key)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid public key format"))?;
    let signature_bytes = Base64::decode_vec(signature)?;
    let sig = EcdsaSignature::from_slice(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;
    verifying_key
        .verify_prehash(&message_hash, &sig)
        .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;
    Ok(true)
}

/// generate a JWT token using the private key and claims, and algorithm ES256K(secp256k1)
pub fn generate_jwt_token(
    private_key_hex: &str,
    claims: serde_json::Value,
) -> anyhow::Result<String> {
    let header_obj = json!({"typ": "JWT","alg": "ES256K"});
    let header = Base64UrlUnpadded::encode_string(serde_json::to_string(&header_obj)?.as_bytes());
    let payload = Base64UrlUnpadded::encode_string(serde_json::to_string(&claims)?.as_bytes());
    let message = format!("{header}.{payload}");
    let signature_bytes = sign_message_bytes(private_key_hex, &message)?;
    let signature = Base64UrlUnpadded::encode_string(signature_bytes.as_slice());
    Ok(format!("{header}.{payload}.{signature}"))
}

//============= aes_gcm =======
//
// Encrypted file layout (v1, self-describing KDF parameters):
//
//   b"DXA1" | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt[16] | nonce[12] | ciphertext
//
// KDF is always Argon2id v0x13 with a 32-byte output for format v1.
//
// Legacy layout (no magic): salt[16] | nonce[12] | ciphertext, derived with the
// argon2 0.5/0.6 defaults (Argon2id v0x13, m=19456, t=2, p=1). Those values are
// pinned below so that legacy files remain decryptable even if the crate's
// defaults change.

const AES_FILE_MAGIC_V1: &[u8; 4] = b"DXA1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Argon2 parameters used when writing new files.
const KDF_M_COST: u32 = 19 * 1024;
const KDF_T_COST: u32 = 2;
const KDF_P_COST: u32 = 1;

/// Argon2 parameters of the legacy (header-less) format, pinned forever.
const LEGACY_M_COST: u32 = 19 * 1024;
const LEGACY_T_COST: u32 = 2;
const LEGACY_P_COST: u32 = 1;

/// Upper bounds for parameters read from a file, so a crafted file cannot make us
/// allocate unbounded memory or spin forever.
const MAX_M_COST: u32 = 4 * 1024 * 1024; // 4 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 64;

fn derive_aes_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> anyhow::Result<Key<Aes256Gcm>> {
    if m_cost > MAX_M_COST || t_cost > MAX_T_COST || p_cost > MAX_P_COST {
        return Err(anyhow::anyhow!(
            "Invalid encrypted file: Argon2 parameters out of range (m={m_cost}, t={t_cost}, p={p_cost})"
        ));
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {e}"))?;
    Ok(Key::<Aes256Gcm>::from(key))
}

fn aes_decrypt(
    key: &Key<Aes256Gcm>,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::try_from(nonce_bytes)?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt file: {e}"))
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Encrypt bytes into the v1 self-describing format.
pub fn encrypt_bytes(plain_bytes: &[u8], password: &str) -> anyhow::Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = try_generate_salt()?;
    let aes_key = derive_aes_key(password, &salt, KDF_M_COST, KDF_T_COST, KDF_P_COST)?;
    let cipher = Aes256Gcm::new(&aes_key);

    let random_nonce = rand::random::<[u8; NONCE_LEN]>();
    let nonce = Nonce::from(random_nonce);
    let ciphertext = cipher
        .encrypt(&nonce, plain_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt file: {e}"))?;

    let mut output = Vec::with_capacity(4 + 12 + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(AES_FILE_MAGIC_V1);
    output.extend_from_slice(&KDF_M_COST.to_le_bytes());
    output.extend_from_slice(&KDF_T_COST.to_le_bytes());
    output.extend_from_slice(&KDF_P_COST.to_le_bytes());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&random_nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt bytes produced by [`encrypt_bytes`], or by the legacy header-less format.
pub fn decrypt_bytes(encrypted: &[u8], password: &str) -> anyhow::Result<Vec<u8>> {
    const V1_HEADER_LEN: usize = 4 + 12 + SALT_LEN + NONCE_LEN;
    if encrypted.len() >= V1_HEADER_LEN && encrypted.starts_with(AES_FILE_MAGIC_V1) {
        let m_cost = read_u32_le(&encrypted[4..8]);
        let t_cost = read_u32_le(&encrypted[8..12]);
        let p_cost = read_u32_le(&encrypted[12..16]);
        let salt = &encrypted[16..16 + SALT_LEN];
        let nonce_bytes = &encrypted[16 + SALT_LEN..V1_HEADER_LEN];
        let ciphertext = &encrypted[V1_HEADER_LEN..];
        let v1_result = derive_aes_key(password, salt, m_cost, t_cost, p_cost)
            .and_then(|key| aes_decrypt(&key, nonce_bytes, ciphertext));
        match v1_result {
            Ok(plain) => return Ok(plain),
            // A legacy file has a random salt, which may start with the magic by chance
            // (probability 2^-32). Fall back to the legacy layout before giving up.
            Err(e) => return decrypt_legacy_bytes(encrypted, password).map_err(|_| e),
        }
    }
    decrypt_legacy_bytes(encrypted, password)
}

fn decrypt_legacy_bytes(encrypted: &[u8], password: &str) -> anyhow::Result<Vec<u8>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN {
        return Err(anyhow::anyhow!("Invalid encrypted file: too short"));
    }
    let salt = &encrypted[0..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];
    let aes_key = derive_aes_key(password, salt, LEGACY_M_COST, LEGACY_T_COST, LEGACY_P_COST)?;
    aes_decrypt(&aes_key, nonce_bytes, ciphertext)
}

/// Write `bytes` to `path` atomically: write a 0600 `<path>.tmp` in the same directory,
/// fsync it, then rename it over `path`. A crash never leaves a half-written `path`.
pub fn write_file_atomic<P: AsRef<Path>>(path: P, bytes: &[u8]) -> anyhow::Result<()> {
    let path = path.as_ref();
    let tmp_path = tmp_path_of(path);
    let result = (|| -> anyhow::Result<()> {
        write_and_sync(&tmp_path, bytes)?;
        fs::rename(&tmp_path, path)?;
        sync_parent_dir(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result?;
    crate::commands::restrict_file_permissions(path);
    Ok(())
}

/// Encrypt `plain_bytes` into `output_file` safely: the ciphertext is written to
/// `<output_file>.tmp` and fsynced, read back and decrypted to verify it round-trips,
/// and only then renamed over `output_file`.
pub fn encrypt_bytes_to_file<P: AsRef<Path>>(
    plain_bytes: &[u8],
    output_file: P,
    password: &str,
) -> anyhow::Result<()> {
    let output_file = output_file.as_ref();
    let tmp_path = tmp_path_of(output_file);
    let result = (|| -> anyhow::Result<()> {
        let encrypted = encrypt_bytes(plain_bytes, password)?;
        write_and_sync(&tmp_path, &encrypted)?;
        // read back from disk and verify before replacing anything
        let verified = decrypt_file_to_bytes(&tmp_path, password)?;
        if verified != plain_bytes {
            return Err(anyhow::anyhow!(
                "verification failed: {} does not decrypt back to the original content",
                tmp_path.display()
            ));
        }
        fs::rename(&tmp_path, output_file)?;
        sync_parent_dir(output_file);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result?;
    crate::commands::restrict_file_permissions(output_file);
    Ok(())
}

pub fn encrypt_file<P: AsRef<Path>>(
    input_file: P,
    output_file: P,
    password: &str,
) -> anyhow::Result<()> {
    let plain_bytes = fs::read(input_file)?;
    encrypt_bytes_to_file(&plain_bytes, output_file, password)
}

pub fn decrypt_file<P: AsRef<Path>>(
    encrypted_file: P,
    output_file: P,
    password: &str,
) -> anyhow::Result<()> {
    let plain_bytes = decrypt_file_to_bytes(encrypted_file, password)?;
    // decrypted key store holds plaintext private keys: written as 0600, atomically
    write_file_atomic(output_file, &plain_bytes)
}

fn tmp_path_of(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Create (or truncate) `path` as owner-only, write `bytes` and fsync.
fn write_and_sync(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file: File = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// fsync the parent directory so a rename survives a crash (best effort, Unix only).
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub fn decrypt_file_to_bytes<P: AsRef<Path>>(
    encrypted_file: P,
    password: &str,
) -> anyhow::Result<Vec<u8>> {
    let encrypted_file_content = fs::read(encrypted_file)?;
    decrypt_bytes(&encrypted_file_content, password)
}

pub fn generate_totp_password(totp_url: &str) -> anyhow::Result<String> {
    let totp = Totp::from_url(totp_url)?;
    Ok(format!("{}", totp.generate_current()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    #[test]
    fn test_signature_and_verify() {
        let public_key = "02f6e5c1a348cd70ee9ebcdf271892878d83d7bb9c1cd0644ae0da0a04904b83e4";
        let private_key = "00d3a1bf3a9a989e3ae11a58e89d95e26d32e0445d825d7fe7ef162ffad2706580";
        let message = "Hello, secp256k1!";
        // Sign the message
        let signature = sign_message(private_key, message).unwrap();
        println!("Signature: {signature}");
        let verify_result = verify_signature(public_key, message, &signature).unwrap();
        assert!(verify_result, "Signature verification failed");
    }

    #[test]
    fn test_jwt_generate() {
        use chrono::Utc;
        let now = Utc::now().timestamp();
        let private_key = "c81efd721a711661296a53b768c780e0d9ec9d597e49d8ed53eed0b638b958cf";
        let claims = json!({
            "sub": "linux-china",
            "kid": "b895c58f944855010fa88f7a76642e2005d51705cb27597c7a85347628ac5dcf",
            "exp": now + 60*60*24*365, // Expiration time (e.g., 2026-01-01T00:00:00Z)
            "iat": now, // now (e.g., 2021-06-01T00:00:00Z)
            "iss": "dotenvx"
        });
        let jwt_token = generate_jwt_token(private_key, claims).unwrap();
        assert_eq!(jwt_token.split('.').count(), 3, "JWT: {jwt_token}");
    }

    #[test]
    fn test_encrypt_decrypt_file_round_trip() -> TestResult {
        // work on copies in a temp dir: never write next to the fixtures in tests/
        let dir = tempfile::tempdir()?;
        let input_file = dir.path().join("example.txt");
        let encrypted_file = dir.path().join("example.txt.aes");
        let output_file = dir.path().join("example.decrypted.txt");
        std::fs::copy("tests/example.txt", &input_file)?;
        let password = "your_secure_password";
        encrypt_file(&input_file, &encrypted_file, password)?;
        let encrypted = std::fs::read(&encrypted_file)?;
        assert_eq!(&encrypted[0..4], b"DXA1");
        decrypt_file(&encrypted_file, &output_file, password)?;
        assert_eq!(std::fs::read(&output_file)?, std::fs::read(&input_file)?);
        assert!(decrypt_file(&encrypted_file, &output_file, "wrong",).is_err());
        Ok(())
    }

    /// Legacy (header-less) file produced by the previous implementation with
    /// `Argon2::default()`; content is "Hello World\n", password "your_secure_password".
    const LEGACY_AES_HEX: &str = "510781d1a75dd63b51192e6713d940a7a9644bf6535a3661f54a298e77de829eb758980aead4088bb392774707c4608b2d686f0561a99207";

    #[test]
    fn test_decrypt_legacy_format() -> TestResult {
        let encrypted = hex::decode(LEGACY_AES_HEX)?;
        let plain = decrypt_bytes(&encrypted, "your_secure_password")?;
        assert_eq!(plain, b"Hello World\n");
        assert!(decrypt_bytes(&encrypted, "wrong").is_err());
        Ok(())
    }

    #[test]
    fn test_encrypt_bytes_v1_roundtrip() -> TestResult {
        let encrypted = encrypt_bytes(b"secret data", "pwd")?;
        assert_eq!(&encrypted[0..4], b"DXA1");
        assert_eq!(read_u32_le(&encrypted[4..8]), KDF_M_COST);
        assert_eq!(read_u32_le(&encrypted[8..12]), KDF_T_COST);
        assert_eq!(read_u32_le(&encrypted[12..16]), KDF_P_COST);
        assert_eq!(decrypt_bytes(&encrypted, "pwd")?, b"secret data");
        assert!(decrypt_bytes(&encrypted, "wrong").is_err());
        Ok(())
    }

    #[test]
    fn test_decrypt_v1_uses_params_from_header() -> TestResult {
        // Build a v1 file with non-default parameters; decryption must honour the header.
        let (m, t, p) = (8 * 1024u32, 3u32, 2u32);
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let key = derive_aes_key("pwd", &salt, m, t, p)?;
        let ct = Aes256Gcm::new(&key)
            .encrypt(&Nonce::from(nonce), b"custom".as_ref())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mut file = b"DXA1".to_vec();
        for v in [m, t, p] {
            file.extend_from_slice(&v.to_le_bytes());
        }
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ct);
        assert_eq!(decrypt_bytes(&file, "pwd")?, b"custom");
        Ok(())
    }

    #[test]
    fn test_decrypt_rejects_bad_input() {
        assert!(decrypt_bytes(b"short", "pwd").is_err());
        let mut file = b"DXA1".to_vec();
        for v in [u32::MAX, 2, 1] {
            file.extend_from_slice(&v.to_le_bytes());
        }
        file.extend_from_slice(&[0u8; SALT_LEN + NONCE_LEN + 16]);
        assert!(decrypt_bytes(&file, "pwd").is_err());
    }
}
