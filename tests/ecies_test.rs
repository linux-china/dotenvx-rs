use base64ct::{Base64, Encoding};
use ecies::utils::generate_keypair;
use ecies::{decrypt, encrypt, PublicKey, SecretKey};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};

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
    // Create signing key from secret key bytes
    let signing_key = SigningKey::from_slice(&sk.serialize()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);
    // Sign the message (k256 handles hashing internally)
    let signature: Signature = signing_key.sign(message.as_bytes());
    let signature_hex = Base64::encode_string(&signature.to_bytes());
    println!("signature: {signature_hex}");
    let result = verifying_key.verify(message.as_bytes(), &signature).is_ok();
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
