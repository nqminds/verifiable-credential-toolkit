use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use verifiable_credential_toolkit::UnsignedVerifiableCredential;

#[derive(Parser)]
#[command(name = "vc-signer")]
#[command(version = "1.0", about = "Signs Verifiable Credentials")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a verifiable credential
    Sign {
        /// Path to the unsigned VC JSON file
        #[arg(short, long)]
        input_vc: PathBuf,

        /// Path to the private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Path to save the signed VC
        #[arg(short, long, default_value = "signed_output.json")]
        output_vc: PathBuf,

        /// Optional schema file path for validation
        #[arg(short, long, conflicts_with = "schema_url")]
        schema: Option<PathBuf>,

        /// Optional schema URL for validation
        #[arg(short = 'u', long, conflicts_with = "schema")]
        schema_url: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::Sign {
            input_vc,
            key,
            output_vc,
            schema,
            schema_url,
        } => {
            // Read the unsigned VC
            let unsigned_vc_str = fs::read_to_string(input_vc)?;
            let unsigned_vc: UnsignedVerifiableCredential = serde_json::from_str(&unsigned_vc_str)?;

            // Read the private key
            let private_key = fs::read(key)?;

            // Sign the VC based on schema validation options
            let signed_vc = if let Some(schema_path) = schema {
                let schema_str = fs::read_to_string(schema_path)?;
                unsigned_vc.sign_with_schema_check(&private_key, &schema_str)?
            } else if let Some(url) = schema_url {
                unsigned_vc.sign_with_schema_check_from_url(private_key, &url)?
            } else {
                unsigned_vc.sign(&private_key)?
            };

            // Save the signed VC
            let signed_vc_str = serde_json::to_string_pretty(&signed_vc)?;
            fs::write(output_vc, signed_vc_str)?;

            println!("Successfully signed the verifiable credential!");
            Ok(())
        }
    }
}
