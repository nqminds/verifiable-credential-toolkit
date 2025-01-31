# Verifiable Credential Toolkit

Tools and Library for Verifiable Credential creation and signing.

# CLI Tools

## `generate_keys`

```
Generates Ed25519 key pairs

Usage: generate_keys [OPTIONS]

Options:
  -o, --output <OUTPUT>  Output directory for the keys [default: .]
  -h, --help             Print help
  -V, --version          Print version
```

## `vc_signer`

```
A CLI tool for signing Verifiable Credentials

Usage: vc_signer <COMMAND>

Commands:
  sign  Sign a verifiable credential
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```
Sign a verifiable credential

Usage: vc_signer sign [OPTIONS] --input-vc <INPUT_VC> --key <KEY>

Options:
  -i, --input-vc <INPUT_VC>      Path to the unsigned VC JSON file
  -k, --key <KEY>                Path to the private key file
  -o, --output-vc <OUTPUT_VC>    Path to save the signed VC [default: signed_output.json]
  -s, --schema <SCHEMA>          Optional schema file path for validation
  -u, --schema-url <SCHEMA_URL>  Optional schema URL for validation
  -h, --help                     Print help
```
