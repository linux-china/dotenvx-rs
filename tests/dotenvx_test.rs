use std::env;
use totp_rs::{Algorithm, Secret, Totp};

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
    let totp = Totp::from_url(totp_url).unwrap();
    println!("{}", totp.generate_current());
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
    println!("{}", totp.to_url().unwrap())
}
