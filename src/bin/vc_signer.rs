use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use verifiable_credential_toolkit::{
    SchemaSource, UnsignedVerifiableCredential, VerifiableCredential,
};

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
        #[cfg(not(target_arch = "wasm32"))] // Only compile schema_url when not targeting wasm32
        #[arg(short = 'u', long, conflicts_with = "schema")]
        schema_url: Option<String>,
    },

    /// Verify a verifiable credential
    Verify {
        /// Path to the signed VC JSON file
        #[arg(short, long)]
        input_vc: PathBuf,

        /// Path to the private key file
        #[arg(short, long)]
        key: PathBuf,
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
            #[cfg(not(target_arch = "wasm32"))] // Only compile schema_url when not targeting wasm32
            schema_url,
        } => {
            // Read the unsigned VC file
            let unsigned_vc_str = fs::read_to_string(input_vc)?;

            // Try to deserialize to UnsignedVerifiableCredential first
            let unsigned_vc: Result<UnsignedVerifiableCredential, _> =
                serde_json::from_str(&unsigned_vc_str);
            let unsigned_vc = match unsigned_vc {
                Ok(vc) => vc,
                Err(_) => {
                    // If deserialization fails, try to deserialize to VerifiableCredential and convert
                    let verifiable_vc: VerifiableCredential =
                        serde_json::from_str(&unsigned_vc_str)?;
                    verifiable_vc.to_unsigned()
                }
            };

            // Read the private key
            let private_key = fs::read(key)?;

            // Resolve the schema source from the CLI options. An inline schema
            // file is loaded here so it outlives the borrow held by SchemaSource.
            let inline_schema = match &schema {
                Some(schema_path) => {
                    let schema_str = fs::read_to_string(schema_path)?;
                    Some(serde_json::from_str::<serde_json::Value>(&schema_str)?)
                }
                None => None,
            };

            let schema_source = if let Some(ref schema_json) = inline_schema {
                SchemaSource::Inline(schema_json)
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    match &schema_url {
                        Some(url) => SchemaSource::Url(url.as_str()),
                        None => SchemaSource::None,
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    SchemaSource::None
                }
            };

            // Validate against the schema (if any) before signing.
            unsigned_vc.validate(&schema_source)?;
            let signed_vc = unsigned_vc.sign(&private_key)?;

            // Save the signed VC
            let signed_vc_str = serde_json::to_string_pretty(&signed_vc)?;
            fs::write(output_vc, signed_vc_str)?;

            println!("Successfully signed the verifiable credential!");
            Ok(())
        }
        Commands::Verify { input_vc, key } => {
            // Read the signed VC file
            let signed_vc_str = fs::read_to_string(input_vc)?;

            // Try to deserialize to UnsignedVerifiableCredential first
            let signed_vc: Result<VerifiableCredential, _> = serde_json::from_str(&signed_vc_str);

            let signed_vc = match signed_vc {
                Ok(vc) => vc,
                Err(_) => {
                    // If deserialization fails, try to deserialize to VerifiableCredential and convert
                    let verifiable_vc: VerifiableCredential = serde_json::from_str(&signed_vc_str)?;
                    verifiable_vc
                }
            };

            // Read the public key
            let public_key = fs::read(key)?;

            // Verify the VC
            let result = signed_vc.verify(&public_key);

            match result {
                Ok(_) => {
                    println!("Successfully verified the verifiable credential!");
                    Ok(())
                }
                Err(err) => Err(err.into()),
            }
        }
    }
}
