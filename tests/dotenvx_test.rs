use std::env;
use totp_rs::{Algorithm, Secret, TOTP};

#[test]
fn test_dotenv_load() {
    // Load the .env file
    dotenvx_rs::dotenv().ok();
    // Check if the environment variable is set
    let value = env::var("HELLO").unwrap();
    println!("HELLO={value}");
}

#[test]
fn test_dotenv_load_example() {
    // Load the .env.example file
    dotenvx_rs::from_path(".env.example").ok();
    // Check if the environment variable is set
    let value = env::var("HELLO").unwrap();
    println!("HELLO={value}");
}

#[test]
fn test_totp() {
    let totp_url = "otpauth://totp/Dotenvx:demo@example.com?secret=VZOQR7AGS6KWMOOKUWFLSTETI74BW4VT&issuer=Dotenvx";
    let totp = TOTP::from_url(totp_url).unwrap();
    println!("{}", totp.generate_current().unwrap());
}

#[test]
fn test_generate_secret() {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::default().to_bytes().unwrap(),
        Some("Dotenvx".to_string()),
        "john@example.com".to_string(),
    ).unwrap();
    println!("{}", totp.get_url())
}
