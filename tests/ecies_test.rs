use base64ct::{Base64, Encoding};
use ecies::utils::generate_keypair;
use ecies::{decrypt, encrypt, PublicKey, SecretKey};
use libsecp256k1::{sign, verify, Message};
use sha2::{Digest, Sha256};

#[test]
fn test_generate_key_pair() {
    // Generate key pairs
    let (sk, pk) = generate_keypair();
    let pk_bytes = &pk.serialize_compressed();
    let pk_hex = hex::encode(pk_bytes);
    let sk_bytes = &sk.serialize();
    let sk_hex = hex::encode(sk_bytes);
    println!("private: {sk_hex}");
    println!("public: {pk_hex}");
}

#[test]
fn test_encrypt() {
    let (sk, pk) = generate_keypair();
    let msg = "hello world".as_bytes();
    let pk_bytes = &pk.serialize_compressed();
    let sk_bytes = &sk.serialize();
    let encrypted_bytes = encrypt(pk_bytes, msg).unwrap();
    let decrypted_byte = decrypt(sk_bytes, &encrypted_bytes).unwrap();
    // convert decrypted bytes to string
    let decrypted_msg = String::from_utf8(decrypted_byte).unwrap();
    println!("{decrypted_msg}");
}

#[test]
fn test_signature() {
    let (sk, pk) = generate_keypair();
    // The message to sign
    let message = "Hello, secp256k1!";
    // Step 1: Hash the message using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();
    let msg = Message::parse_slice(message_hash.as_slice()).unwrap();
    let signature = sign(&msg, &sk).0;
    let signature_hex = Base64::encode_string(&signature.serialize());
    println!("signature: {signature_hex}");
    let result = verify(&msg, &signature, &pk);
    println!("verify result: {result}");
}

#[test]
fn test_parse_private_key() {
    let sk_hex = "9e70188d351c25d0714929205df9b8f4564b6b859966bdae7aef7f752a749d8b";
    let sk_bytes = hex::decode(sk_hex).unwrap();
    let sk = SecretKey::parse_slice(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&sk);
    let pk_bytes = &pk.serialize_compressed();
    let pk_hex = hex::encode(pk_bytes);
    println!("public key: {pk_hex}");
}
