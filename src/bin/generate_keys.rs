use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use verifiable_credential_toolkit::generate_keypair;

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

    let (signing_key, verifying_key): ([u8; 32], [u8; 32]) = generate_keypair();

    // Get the current time for the file names
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)?;
    let datetime = since_the_epoch.as_secs();

    // Save the public key (32 bytes)
    let pub_path = cli.output.join(format!("{datetime}.pub"));
    let mut pub_file = File::create(&pub_path)?;
    pub_file.write_all(&verifying_key)?;
    println!("Public key saved to: {}", pub_path.display());

    // Save the private key (32 bytes)
    let priv_path = cli.output.join(format!("{datetime}.priv"));
    let mut priv_file = File::create(&priv_path)?;
    priv_file.write_all(&signing_key)?;
    println!("Private key saved to: {}", priv_path.display());

    Ok(())
}
