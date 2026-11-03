//! Tests of the `dotenvx_rs` library API.
//!
//! Each test uses its own key pair and a unique profile name, the private key is passed through
//! the `DOTENV_PRIVATE_KEY_{PROFILE}` environment variable, so the tests don't depend on (or touch)
//! any `.env.keys` file or global key store and don't interfere with each other.

use dotenvx_rs::common::{find_env_file_path, get_profile_name_from_file};
use dotenvx_rs::dotenvx::{
    decrypt_dotenvx_item, encrypt_dotenvx_item, from_filename, from_filename_iter, from_path,
    from_path_iter, from_read_iter, get_private_key,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::Path;

struct KeyPair {
    sk: String,
    pk: String,
}

fn key_pair() -> KeyPair {
    let (sk, pk) = ecies::utils::generate_keypair();
    KeyPair {
        sk: hex::encode(sk.serialize()),
        pk: hex::encode(pk.serialize_compressed()),
    }
}

/// unique, lower case profile name
fn unique_profile() -> String {
    format!("t{}", uuid::Uuid::now_v7().simple())
}

/// Write `.env.{profile}` with an encrypted `SECRET` and a plain `PLAIN` entry,
/// and export the private key as `DOTENV_PRIVATE_KEY_{PROFILE}`.
fn write_profile_env_file(
    dir: &Path,
    profile: &str,
    kp: &KeyPair,
    secret: &str,
) -> std::path::PathBuf {
    let upper = profile.to_uppercase();
    let encrypted = encrypt_dotenvx_item(&kp.pk, secret).unwrap();
    let path = dir.join(format!(".env.{profile}"));
    fs::write(
        &path,
        format!(
            "DOTENV_PUBLIC_KEY_{upper}=\"{}\"\n{upper}_SECRET=\"{encrypted}\"\n{upper}_PLAIN=plain-value\n",
            kp.pk
        ),
    )
    .unwrap();
    unsafe { env::set_var(format!("DOTENV_PRIVATE_KEY_{upper}"), &kp.sk) };
    path
}

#[test]
fn encrypt_and_decrypt_item_round_trip() {
    let kp = key_pair();
    let encrypted = encrypt_dotenvx_item(&kp.pk, "hello 世界").unwrap();
    assert!(encrypted.starts_with("encrypted:"));
    // different ciphertext every time (ephemeral key)
    assert_ne!(
        encrypted,
        encrypt_dotenvx_item(&kp.pk, "hello 世界").unwrap()
    );
    assert_eq!(
        decrypt_dotenvx_item(&kp.sk, &encrypted).unwrap(),
        "hello 世界"
    );
    // the `encrypted:` prefix is optional
    let without_prefix = encrypted.strip_prefix("encrypted:").unwrap();
    assert_eq!(
        decrypt_dotenvx_item(&kp.sk, without_prefix).unwrap(),
        "hello 世界"
    );
}

#[test]
fn from_path_iter_decrypts_entries_without_touching_env() {
    let dir = tempfile::tempdir().unwrap();
    let profile = unique_profile();
    let upper = profile.to_uppercase();
    let kp = key_pair();
    let path = write_profile_env_file(dir.path(), &profile, &kp, "s3cr3t");

    let items: HashMap<String, String> = from_path_iter(&path).unwrap().into_iter().collect();
    assert_eq!(items[&format!("{upper}_SECRET")], "s3cr3t");
    assert_eq!(items[&format!("{upper}_PLAIN")], "plain-value");
    assert!(
        env::var(format!("{upper}_SECRET")).is_err(),
        "iter must not set env vars"
    );

    let items: HashMap<String, String> = from_filename_iter(&path).unwrap().into_iter().collect();
    assert_eq!(items[&format!("{upper}_SECRET")], "s3cr3t");
}

#[test]
fn from_path_iter_fails_without_matching_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let profile = unique_profile();
    let upper = profile.to_uppercase();
    let kp = key_pair();
    let path = write_profile_env_file(dir.path(), &profile, &kp, "s3cr3t");
    // replace the private key with one that doesn't match the declared public key
    unsafe { env::set_var(format!("DOTENV_PRIVATE_KEY_{upper}"), key_pair().sk) };
    assert!(from_path_iter(&path).is_err());
}

#[test]
fn from_path_loads_decrypted_values_into_env() {
    let dir = tempfile::tempdir().unwrap();
    let profile = unique_profile();
    let upper = profile.to_uppercase();
    let kp = key_pair();
    let path = write_profile_env_file(dir.path(), &profile, &kp, "s3cr3t");
    // existing variables are overridden for security reasons
    unsafe { env::set_var(format!("{upper}_PLAIN"), "old") };

    from_path(&path).unwrap();
    assert_eq!(env::var(format!("{upper}_SECRET")).unwrap(), "s3cr3t");
    assert_eq!(env::var(format!("{upper}_PLAIN")).unwrap(), "plain-value");
}

#[test]
fn from_filename_loads_env_and_reports_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let profile = unique_profile();
    let upper = profile.to_uppercase();
    let kp = key_pair();
    let path = write_profile_env_file(dir.path(), &profile, &kp, "s3cr3t");

    assert_eq!(from_filename(&path).unwrap(), path);
    assert_eq!(env::var(format!("{upper}_SECRET")).unwrap(), "s3cr3t");
    assert!(from_filename(dir.path().join(".env.does-not-exist")).is_err());
}

#[test]
fn from_read_iter_returns_plain_entries_without_public_key() {
    let content = "A=1\nB=\"two words\"\n";
    let items: HashMap<String, String> = from_read_iter(Cursor::new(content))
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(items["A"], "1");
    assert_eq!(items["B"], "two words");
}

#[test]
fn get_private_key_from_profile_env_var_must_match_public_key() {
    let profile = unique_profile();
    let upper = profile.to_uppercase();
    let kp = key_pair();
    unsafe { env::set_var(format!("DOTENV_PRIVATE_KEY_{upper}"), &kp.sk) };
    let profile = Some(profile);
    assert_eq!(get_private_key(&None, &profile).unwrap(), kp.sk);
    assert_eq!(
        get_private_key(&Some(kp.pk.clone()), &profile).unwrap(),
        kp.sk
    );
    assert!(get_private_key(&Some(key_pair().pk), &profile).is_err());
}

#[test]
fn profile_name_from_file_name() {
    assert_eq!(get_profile_name_from_file(".env"), None);
    assert_eq!(
        get_profile_name_from_file(".env.prod").as_deref(),
        Some("prod")
    );
    assert_eq!(
        get_profile_name_from_file("config/.env.test").as_deref(),
        Some("test")
    );
    assert_eq!(
        get_profile_name_from_file(r"config\.env.dev").as_deref(),
        Some("dev")
    );
    assert_eq!(get_profile_name_from_file("application.properties"), None);
    assert_eq!(
        get_profile_name_from_file("src/main/resources/application-prod.properties").as_deref(),
        Some("prod")
    );
}

#[test]
fn find_env_file_path_searches_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a/b/c");
    fs::create_dir_all(&nested).unwrap();
    fs::write(dir.path().join("a/.env.local-test"), "A=1\n").unwrap();
    assert_eq!(
        find_env_file_path(&nested, ".env.local-test"),
        Some(dir.path().join("a/.env.local-test"))
    );
    let missing = format!(".env.{}", unique_profile());
    assert_eq!(find_env_file_path(&nested, &missing), None);
}
