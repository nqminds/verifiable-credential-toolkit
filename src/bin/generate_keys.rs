use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Generate a new Ed25519 key pair
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    // Get the current time for the file names
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    let datetime = since_the_epoch.as_secs();

    // Save the public key
    let mut pub_file = File::create(format!("tests/test_data/keys/{}.pub", datetime)).unwrap();
    pub_file.write_all(key_pair.public_key().as_ref()).unwrap();

    // Save the private key
    let mut priv_file = File::create(format!("tests/test_data/keys/{}.priv", datetime)).unwrap();
    priv_file.write_all(pkcs8_bytes.as_ref()).unwrap();
}
