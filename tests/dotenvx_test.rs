use std::env;
use totp_rs::{Algorithm, Secret, Totp};

#[test]
#[ignore = "needs the private key of the repository's .env and mutates the process environment"]
fn test_dotenv_load() {
    // Load the .env file
    dotenvx_rs::dotenv().ok();
    // Check if the environment variable is set
    assert_eq!(env::var("HELLO").unwrap(), "World");
}

#[test]
#[ignore = "needs the private key of .env.example and mutates the process environment"]
fn test_dotenv_load_example() {
    // Load the .env.example file
    dotenvx_rs::from_path(".env.example").ok();
    // Check if the environment variable is set
    assert!(!env::var("HELLO").unwrap().starts_with("encrypted:"));
}

#[test]
fn test_totp() {
    let totp_url = "otpauth://totp/Dotenvx:demo@example.com?secret=VZOQR7AGS6KWMOOKUWFLSTETI74BW4VT&issuer=Dotenvx";
    let totp = Totp::from_url(totp_url).unwrap();
    let code = totp.generate_current().to_string();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(totp.check_current(&code).is_some());
}

#[test]
fn test_generate_secret() {
    let totp = totp_rs::Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::default().as_bytes())
        .with_account_name("john@example.com".to_string())
        .build()
        .unwrap();
    let url = totp.to_url().unwrap();
    assert!(url.starts_with("otpauth://totp/"), "{url}");
    assert!(url.contains("john%40example.com") || url.contains("john@example.com"), "{url}");
}
