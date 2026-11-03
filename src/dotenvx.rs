use crate::common::{find_env_file_path, get_profile_name_from_env, get_profile_name_from_file};
use base64ct::{Base64, Encoding};
use env::set_var;
use std::collections::HashMap;
use std::env;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};

/// load/decrypt .env file recursively from current directory to root directory
/// if profile name detected in environment, such as `NODE_ENV`, `RUN_ENV`, `APP_ENV` is set in env, it will load .env.{profile} file
pub fn dotenv() -> dotenvy::Result<()> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    let env_file_path =
        find_env_file_path(&env::current_dir().map_err(dotenvy::Error::Io)?, &env_file);
    if let Some(path) = env_file_path {
        return from_path_with_dotenvx(&path, true);
    }
    Ok(())
}

/// load/decrypt .env file recursively from current directory to root directory as a HashMap
pub fn dotenv_entries() -> dotenvy::Result<HashMap<String, String>> {
    // load profile env
    let profile_name = get_profile_name_from_env();
    let env_file = if let Some(name) = &profile_name {
        format!(".env.{name}")
    } else {
        ".env".to_owned()
    };
    let mut entries = HashMap::new();
    let env_file_path =
        find_env_file_path(&env::current_dir().map_err(dotenvy::Error::Io)?, &env_file);
    if let Some(path) = env_file_path {
        // propagate the read/decrypt error: an empty map means "no variables", not "failed" (review #9)
        entries.extend(from_path_iter(path)?);
    }
    Ok(entries)
}

/// same as [`dotenv`]: find .env (or .env.{profile}) from current directory to root directory
pub fn dotenv_override() -> dotenvy::Result<()> {
    dotenv()
}

pub fn dotenv_iter<P: AsRef<Path>>() -> dotenvy::Result<Vec<(String, String)>> {
    let public_key = get_public_key(".env");
    let private_key = private_key_for_file(&public_key, &None, Path::new(".env"));
    let mut items: Vec<(String, String)> = vec![];
    for x in dotenvy::dotenv_iter()? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, &public_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

/// load/decrypt env_file from a given path
pub fn from_path<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<()> {
    from_path_with_dotenvx(&env_file, true)
}

pub fn from_path_override<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<()> {
    from_path_with_dotenvx(&env_file, true)
}

pub fn from_path_iter<P: AsRef<Path>>(env_file: P) -> dotenvy::Result<Vec<(String, String)>> {
    let profile_name = profile_name_of_path(env_file.as_ref());
    let public_key = get_public_key(&env_file);
    let private_key = private_key_for_file(&public_key, &profile_name, env_file.as_ref());
    let mut items: Vec<(String, String)> = vec![];
    for x in dotenvy::from_path_iter(env_file)? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, &public_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

pub fn from_filename<P: AsRef<Path>>(filename: P) -> dotenvy::Result<PathBuf> {
    let path = filename.as_ref().to_path_buf();
    if !path.exists() {
        return Err(dotenvy::Error::Io(std::io::Error::from(
            ErrorKind::NotFound,
        )));
    }
    from_path_with_dotenvx(&path, true)?;
    Ok(path)
}

pub fn from_filename_override<P: AsRef<Path>>(filename: P) -> dotenvy::Result<PathBuf> {
    let path = filename.as_ref().to_path_buf();
    if !path.exists() {
        return Err(dotenvy::Error::Io(std::io::Error::from(
            ErrorKind::NotFound,
        )));
    }
    from_path_with_dotenvx(&path, true)?;
    Ok(path)
}

pub fn from_filename_iter<P: AsRef<Path>>(filename: P) -> dotenvy::Result<Vec<(String, String)>> {
    let mut items: Vec<(String, String)> = vec![];
    let profile_name = profile_name_of_path(filename.as_ref());
    let public_key = get_public_key(&filename);
    let private_key = private_key_for_file(&public_key, &profile_name, filename.as_ref());
    for x in dotenvy::from_filename_iter(filename)? {
        let (key, value) = x?;
        let plain_value = check_and_decrypt(&private_key, &public_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

pub fn from_read<R: Read>(reader: R) -> dotenvy::Result<()> {
    from_read_with_dotenvx(reader)
}

pub fn from_read_iter<R: Read>(reader: R) -> dotenvy::Result<Vec<(String, String)>> {
    let mut items: Vec<(String, String)> = vec![];
    let entries = dotenvy::from_read_iter(reader).collect::<dotenvy::Result<Vec<_>>>()?;
    let public_key = get_public_key_from_entries(&entries);
    let private_key =
        get_private_key(&public_key, &get_profile_name_from_env()).map_err(|e| e.to_string());
    for (key, value) in entries {
        let plain_value = check_and_decrypt(&private_key, &public_key, value)?;
        items.push((key, plain_value));
    }
    Ok(items)
}

fn from_path_with_dotenvx<P: AsRef<Path>>(env_file: P, is_override: bool) -> dotenvy::Result<()> {
    if env_file.as_ref().exists() {
        let dotenv_content = std::fs::read_to_string(&env_file).map_err(dotenvy::Error::Io)?;
        if dotenv_content.contains("encrypted:") {
            let public_key = get_public_key(&env_file);
            let profile_name = profile_name_of_path(env_file.as_ref());
            let private_key = Ok(private_key_for_file(&public_key, &profile_name, env_file.as_ref())
                .map_err(private_key_not_found)?);
            for item in dotenvy::from_filename_iter(&env_file)? {
                let (key, value) = item?;
                let env_value = check_and_decrypt(&private_key, &public_key, value)?;
                set_env_var(&key, env_value, is_override);
            }
        } else if is_override {
            dotenvy::from_filename_override(&env_file)?;
        } else {
            dotenvy::from_filename(env_file)?;
        }
    }
    Ok(())
}

fn get_public_key<P: AsRef<Path>>(env_file: P) -> Option<String> {
    // stop at the first error: reading a directory yields `Err` forever, `find` would never return
    let entries = dotenvy::from_path_iter(env_file)
        .ok()?
        .map_while(Result::ok)
        .collect::<Vec<_>>();
    get_public_key_from_entries(&entries)
}

fn get_public_key_from_entries(entries: &[(String, String)]) -> Option<String> {
    entries
        .iter()
        .find(|(key, _)| key.starts_with("DOTENV_PUBLIC_KEY"))
        .map(|(_, value)| value.trim_matches(|c| c == '"' || c == '\'').to_string())
}

fn from_read_with_dotenvx<R: Read>(reader: R) -> dotenvy::Result<()> {
    let entries = dotenvy::from_read_iter(reader).collect::<dotenvy::Result<Vec<_>>>()?;
    let public_key = get_public_key_from_entries(&entries);
    // only look up the private key when there is something to decrypt, like `from_path` (review #12)
    let private_key = if entries.iter().any(|(_, value)| value.starts_with("encrypted:")) {
        get_private_key(&public_key, &get_profile_name_from_env()).map_err(|e| e.to_string())
    } else {
        Err("no encrypted value".to_owned())
    };
    // decrypt everything before touching the environment: a failure must not leave it half loaded
    let mut items = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        items.push((key, check_and_decrypt(&private_key, &public_key, value)?));
    }
    for (key, value) in items {
        set_env_var(&key, value, true);
    }
    Ok(())
}

/// Find the private key. `public_key` is the public key declared by the env file: when given, the private key
/// must match it. The lookup is shared with the CLI, see [`crate::common::find_private_key`] for the order;
/// `.env.keys` is searched from the current directory upward.
pub fn get_private_key(
    public_key: &Option<String>,
    profile_name: &Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(crate::common::find_private_key(
        public_key.as_deref(),
        profile_name,
        None,
    )?)
}

/// Same as [`get_private_key`], but the `.env.keys` next to (or above) `env_file` is searched first.
fn private_key_for_file(
    public_key: &Option<String>,
    profile_name: &Option<String>,
    env_file: &Path,
) -> Result<String, String> {
    crate::common::find_private_key(public_key.as_deref(), profile_name, Some(env_file))
}

/// `dotenvy::Error::Io` with `ErrorKind::NotFound` and the reason, instead of a bare `EnvVar(NotPresent)`
fn private_key_not_found(message: String) -> dotenvy::Error {
    dotenvy::Error::Io(io::Error::new(ErrorKind::NotFound, message))
}

// if the encrypted text starts with "encrypted:", it will decrypt it.
// `public_key` is the one declared by the env file: without it the private key could not be verified,
// so a decryption failure says so instead of a bare ecies error (review #12)
fn check_and_decrypt(
    private_key: &Result<String, String>,
    public_key: &Option<String>,
    encrypted_text: String,
) -> dotenvy::Result<String> {
    if let Some(tripped_value) = encrypted_text.strip_prefix("encrypted:") {
        match private_key {
            Ok(private_key) => decrypt_dotenvx_item(private_key, tripped_value).map_err(|e| {
                if public_key.is_some() {
                    e
                } else {
                    invalid_data(format!(
                        "{e} (no DOTENV_PUBLIC_KEY in the env file, the private key found may belong to another env file)"
                    ))
                }
            }),
            Err(message) => Err(private_key_not_found(message.clone())),
        }
    } else {
        Ok(encrypted_text)
    }
}

/// decrypt dotenvx encrypted item with the given private key
/// the encrypted text can be with or without the "encrypted:" prefix
pub fn decrypt_dotenvx_item(private_key: &str, encrypted_text: &str) -> dotenvy::Result<String> {
    let base64_text = encrypted_text
        .strip_prefix("encrypted:")
        .unwrap_or(encrypted_text);
    let encrypted_bytes = crate::common::decode_base64_lenient(base64_text)
        .map_err(|e| invalid_data(format!("invalid base64 in encrypted value: {e}")))?;
    let sk = hex::decode(private_key.trim())
        .map_err(|e| invalid_data(format!("invalid private key hex: {e}")))?;
    let decrypted_bytes = ecies::decrypt(&sk, &encrypted_bytes)
        .map_err(|e| invalid_data(format!("failed to decrypt value: {e}")))?;
    String::from_utf8(decrypted_bytes)
        .map_err(|e| invalid_data(format!("decrypted value is not valid UTF-8: {e}")))
}

/// encrypt dotenvx item with the given public key
/// the returned encrypted text is with the "encrypted:" prefix
pub fn encrypt_dotenvx_item(public_key: &str, plain_text: &str) -> dotenvy::Result<String> {
    let pk = hex::decode(public_key.trim())
        .map_err(|e| invalid_data(format!("invalid public key hex: {e}")))?;
    let encrypted_bytes = ecies::encrypt(&pk, plain_text.as_bytes())
        .map_err(|e| invalid_data(format!("failed to encrypt value: {e}")))?;
    let base64_text = Base64::encode_string(&encrypted_bytes);
    Ok(format!("encrypted:{base64_text}"))
}

/// `dotenvy::Error::Io` with `ErrorKind::InvalidData`, used for bad keys / corrupted ciphertext
fn invalid_data(message: String) -> dotenvy::Error {
    dotenvy::Error::Io(io::Error::new(ErrorKind::InvalidData, message))
}

/// profile name from the file name of the path, `None` if the path has no (UTF-8) file name, e.g. `..`
fn profile_name_of_path(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(get_profile_name_from_file)
}

fn set_env_var(key: &str, env_value: String, is_override: bool) {
    unsafe {
        if is_override || env::var(key).is_err() {
            set_var(key, env_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;

    #[test]
    fn test_from_read_without_encrypted_value_needs_no_private_key() {
        // a key name unique to this test, so the environment can not interfere
        let key = format!("DOTENVX_FROM_READ_{}", uuid::Uuid::now_v7().simple());
        from_read(Cursor::new(format!("{key}=plain\n"))).unwrap();
        assert_eq!(env::var(&key).unwrap(), "plain");
    }

    #[test]
    #[ignore = "needs the private key of the repository's .env and mutates the process environment"]
    fn test_load() {
        unsafe {
            set_var("HELLO", "Jackie");
        }
        dotenv_override().unwrap();
        assert_eq!(env::var("HELLO").unwrap(), "World");
    }

    #[test]
    fn test_get_public_key_from_entries() {
        let pk = "02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0";
        let entries = vec![
            ("HELLO".to_string(), "World".to_string()),
            ("DOTENV_PUBLIC_KEY".to_string(), pk.to_string()),
        ];
        assert_eq!(get_public_key_from_entries(&entries).as_deref(), Some(pk));

        let entries = vec![("DOTENV_PUBLIC_KEY_PROD".to_string(), format!("\"{pk}\""))];
        assert_eq!(get_public_key_from_entries(&entries).as_deref(), Some(pk));

        let entries = vec![("HELLO".to_string(), "World".to_string())];
        assert_eq!(get_public_key_from_entries(&entries), None);
    }

    #[test]
    #[ignore = "needs the private key of the repository's .env"]
    fn test_ecies_decrypt() {
        let encrypted_text = "encrypted:BNexEwjKwt87k9aEgaSng1JY6uW8OkwMYEFTwEy/xyzDrQwQSDIUEXNlcwWi6rnvR1Q60G35NO4NWwhUYAaAON1LOnvMk+tJjTQJaM8DPeX2AJ8IzoTV44FLJsbOiMa77RLrnBv7";
        let private_key = get_private_key(&None, &None).unwrap();
        println!("private_key: {private_key}");
        let text = decrypt_dotenvx_item(&private_key, encrypted_text).unwrap();
        assert_eq!(text, "World");
    }

    #[test]
    #[ignore = "needs the private key of the repository's .env and mutates the process environment"]
    fn test_load_from_reader() {
        let dotenv_content = fs::read_to_string(".env").unwrap();
        let reader = Cursor::new(dotenv_content.as_bytes());
        from_read(reader).unwrap();
        assert_eq!(env::var("HELLO").unwrap(), "World");
        // Assuming the private key is set correctly in the environment,
        // The decryption will depend on the actual private key used
    }
    /// self-contained: generated key pair, the private key is passed via `DOTENV_PRIVATE_KEY`
    /// (verified against the public key, so it can't be picked up by other tests by mistake)
    #[test]
    fn test_load_from_reader_iterator() {
        let (sk, pk) = ecies::utils::generate_keypair();
        let sk_hex = hex::encode(sk.serialize());
        let pk_hex = hex::encode(pk.serialize_compressed());
        let encrypted = encrypt_dotenvx_item(&pk_hex, "World").unwrap();
        let content = format!("DOTENV_PUBLIC_KEY={pk_hex}\nHELLO={encrypted}\nPLAIN=text\n");
        unsafe { env::set_var("DOTENV_PRIVATE_KEY", &sk_hex) };
        let items = from_read_iter(Cursor::new(content.as_bytes()));
        unsafe { env::remove_var("DOTENV_PRIVATE_KEY") };
        let items: HashMap<String, String> = items.unwrap().into_iter().collect();
        assert_eq!(items.get("HELLO").map(String::as_str), Some("World"));
        assert_eq!(items.get("PLAIN").map(String::as_str), Some("text"));
    }

    #[test]
    fn test_decrypt_corrupted_value_returns_error() {
        let (sk, pk) = ecies::utils::generate_keypair();
        let sk_hex = hex::encode(sk.serialize());
        let pk_hex = hex::encode(pk.serialize_compressed());
        let encrypted = encrypt_dotenvx_item(&pk_hex, "hello").unwrap();
        // flip the first base64 char of the ciphertext: B -> C (invalid ephemeral public key)
        let corrupted = encrypted.replacen("encrypted:B", "encrypted:C", 1);
        let err = decrypt_dotenvx_item(&sk_hex, &corrupted).unwrap_err();
        assert!(matches!(err, dotenvy::Error::Io(ref e) if e.kind() == ErrorKind::InvalidData));
        // invalid base64 / private key / public key
        assert!(decrypt_dotenvx_item(&sk_hex, "encrypted:%%%").is_err());
        assert!(decrypt_dotenvx_item("not-hex", &encrypted).is_err());
        assert!(encrypt_dotenvx_item("not-hex", "hello").is_err());
        assert!(encrypt_dotenvx_item("00", "hello").is_err());
        // the wrong private key fails instead of panicking
        let (other_sk, _) = ecies::utils::generate_keypair();
        assert!(decrypt_dotenvx_item(&hex::encode(other_sk.serialize()), &encrypted).is_err());
    }

    #[test]
    fn test_from_read_iter_parse_error_returns_error() {
        let result = from_read_iter(Cursor::new("A='unterminated\n".as_bytes()));
        assert!(matches!(result, Err(dotenvy::Error::LineParse(..))));
        assert!(from_read(Cursor::new("A='unterminated\n".as_bytes())).is_err());
    }

    #[test]
    fn test_path_without_file_name_does_not_panic() {
        assert_eq!(profile_name_of_path(Path::new("..")), None);
        assert_eq!(profile_name_of_path(Path::new("/")), None);
        assert!(from_path_iter("..").is_err());
        assert!(from_filename_iter("..").is_err());
    }

    #[test]
    #[ignore = "depends on the repository's .env.keys of this machine"]
    fn test_find_private_key() {
        // the public key declared in the project's .env, its private key lives in .env.keys
        let public_key = "02b4972559803fa3c2464e93858f80c3a4c86f046f725329f8975e007b393dc4f0";
        let private_key = get_private_key(&Some(public_key.to_string()), &None)
            .expect("Failed to get a private key");
        assert_eq!(
            crate::common::public_key_of_private_key(&private_key).as_deref(),
            Some(public_key)
        );
    }

    #[test]
    fn test_get_private_key_verifies_public_key() {
        let (sk, pk) = ecies::utils::generate_keypair();
        let (other_sk, _) = ecies::utils::generate_keypair();
        let sk_hex = hex::encode(sk.serialize());
        let pk_hex = hex::encode(pk.serialize_compressed());
        assert_eq!(
            crate::common::public_key_of_private_key(&sk_hex).as_deref(),
            Some(pk_hex.as_str())
        );
        let profile = format!("t{}", uuid::Uuid::now_v7().simple());
        let key_name = format!("DOTENV_PRIVATE_KEY_{}", profile.to_uppercase());
        let profile_name = Some(profile);
        unsafe { env::set_var(&key_name, hex::encode(other_sk.serialize())) };
        // the mismatched key is never returned for the public key
        assert!(get_private_key(&Some(pk_hex.clone()), &profile_name).is_err());
        unsafe { env::set_var(&key_name, &sk_hex) };
        assert_eq!(
            get_private_key(&Some(pk_hex), &profile_name).unwrap(),
            sk_hex
        );
        unsafe { env::remove_var(&key_name) };
    }
}
