use clap::Parser;
use ring::signature::{Ed25519KeyPair, KeyPair};
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

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Generate a new Ed25519 key pair
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Get the current time for the file names
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    let datetime = since_the_epoch.as_secs();

    // Save the public key
    let pub_path = cli.output.join(format!("{datetime}.pub"));
    let mut pub_file = File::create(&pub_path).unwrap();
    pub_file.write_all(key_pair.public_key().as_ref()).unwrap();
    println!("Public key saved to: {}", pub_path.display());

    // Save the private key
    let priv_path = cli.output.join(format!("{datetime}.priv"));
    let mut priv_file = File::create(&priv_path).unwrap();
    priv_file.write_all(pkcs8_bytes.as_ref()).unwrap();
    println!("Private key saved to: {}", priv_path.display());
}
