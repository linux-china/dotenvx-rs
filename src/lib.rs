//! # Dotenvx
//!
//! A library to load environment variables from `.env` files with encrypted mode, and compatible with dotenv api.
//! # Features
//! - Load environment variables from `.env` files.
//! - Support for decrypting environment variables.
//! - Support for profile environment variables, such as `NODE_ENV`, `RUN_ENV`, `APP_ENV`, `SPRING_PROFILES_ACTIVE`, `STELA_ENV`.
//! - Override existing environment variables by default because of security consideration.
//!
//! # Examples
//!
//! ```
//! use dotenvx_rs::dotenvx;
//!
//! dotenvx::dotenv().ok();
//! ```

pub mod common;
pub mod dotenvx;

pub use dotenvx::{dotenv, from_path, dotenv_entries};
