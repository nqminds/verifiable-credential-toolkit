use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// CLI for generating Ed25519 key pairs
#[derive(Parser)]
#[command(version = "1.0", about = "Generates Ed25519 key pairs")]
struct Cli {
    /// Output directory for the keys
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Generate a new Ed25519 key pair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Get the current time for the file names
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
    let datetime = since_the_epoch.as_secs();

    // Save the public key (32 bytes)
    let pub_path = cli.output.join(format!("{datetime}.pub"));
    let mut pub_file = File::create(&pub_path)?;
    pub_file.write_all(verifying_key.as_bytes())?;
    println!("Public key saved to: {}", pub_path.display());

    // Save the private key (32 bytes)
    let priv_path = cli.output.join(format!("{datetime}.priv"));
    let mut priv_file = File::create(&priv_path)?;
    priv_file.write_all(signing_key.to_bytes().as_ref())?;
    println!("Private key saved to: {}", priv_path.display());

    Ok(())
}