# Verifiable Credential Toolkit

A Rust library (with WASM/JavaScript bindings) for creating, signing, and verifying [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/). It uses Ed25519 digital signatures to ensure credentials are tamper-proof and can be independently verified.

## Table of Contents

- [What Are Verifiable Credentials?](#what-are-verifiable-credentials)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Usage](#usage)
  - [Rust Library](#rust-library)
  - [Command-Line Tools](#command-line-tools)
  - [JavaScript / TypeScript (WASM)](#javascript--typescript-wasm)
- [API Reference](#api-reference)
- [JSON Schema Validation](#json-schema-validation)
- [Examples](#examples)
- [Verifiable Presentations](#verifiable-presentations)
- [Security Considerations](#security-considerations)

---

## What Are Verifiable Credentials?

Verifiable Credentials (VCs) are a W3C standard for expressing credentials (e.g. identity documents, certificates, attestations about devices or people) in a way that is:

- **Tamper-evident** — any modification to the credential after signing is detectable.
- **Machine-readable** — credentials are structured JSON that software can parse and validate.
- **Decentralised** — no central authority is needed to verify a credential; anyone with the issuer's public key can check it.

A typical VC workflow looks like this:

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Issuer  │         │  Holder  │         │ Verifier │
│          │         │          │         │          │
│ Creates  │ Signed  │ Stores & │ Presents│ Checks   │
│ & signs  ├────────►│ carries  ├────────►│ signature│
│ the VC   │   VC    │ the VC   │   VC    │ & data   │
└──────────┘         └──────────┘         └──────────┘
```

1. An **Issuer** (e.g. a device manufacturer, certificate authority) creates a credential containing claims (e.g. "this device has ID X and model Y") and signs it with their private key.
2. A **Holder** (e.g. the device owner) receives and stores the signed credential.
3. A **Verifier** (e.g. a system accepting the device onto a network) checks the signature using the issuer's public key. If valid, the claims are trustworthy.

This toolkit handles steps 1 and 3 — signing credentials and verifying them.

---

## Quick Start

### Rust

```rust
use verifiable_credential_toolkit::{
    UnsignedVerifiableCredential, generate_keypair,
};

// 1. Generate an Ed25519 keypair (signing_key: SigningKey, verifying_key: VerifyingKey)
let keypair = generate_keypair();

// 2. Define a credential as JSON
let vc_json = r#"{
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "https://example.com/issuers/sensor-manufacturer",
    "credentialSubject": {
        "id": "urn:uuid:device-001",
        "name": "Temperature Sensor A"
    }
}"#;

// 3. Parse and sign
let unsigned_vc: UnsignedVerifiableCredential =
    serde_json::from_str(vc_json).expect("Invalid VC JSON");
let signed_vc = unsigned_vc.sign(&keypair.signing_key).expect("Signing failed");

// 4. Verify
signed_vc.verify(&keypair.verifying_key).expect("Verification failed");
println!("Credential verified successfully!");
```

### JavaScript (Node.js)

```js
import {
  sign,
  verify,
  generate_keypair,
} from "./pkg/verifiable_credential_toolkit.js";

// 1. Generate keys
const keypair = generate_keypair();

// 2. Create an unsigned credential
const unsignedVC = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: ["VerifiableCredential"],
  issuer: "https://example.com/issuers/sensor-manufacturer",
  credentialSubject: {
    id: "urn:uuid:device-001",
    name: "Temperature Sensor A",
  },
};

// 3. Sign and verify
const signedVC = sign(unsignedVC, keypair.signing_key());
const isValid = verify(signedVC, keypair.verifying_key());
console.log("Valid:", isValid); // true
```

---

## Installation

### As a Rust dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
verifiable-credential-toolkit = "0.5"
```

Or install directly from GitHub:

```toml
[dependencies]
verifiable-credential-toolkit = { git = "https://github.com/nqminds/verifiable-credential-toolkit" }
```

The protobuf Rust bindings are generated automatically at build time from
`src/proto_schemas/vc.proto` into Cargo's build output directory, so the generated
`.rs` files do not need to be committed. `protoc` is supplied by the vendored
build dependency used in `build.rs`.

### As a WASM/JavaScript package

You need the `wasm32-unknown-unknown` Rust target and the [`wasm-bindgen-cli`](https://github.com/wasm-bindgen/wasm-bindgen#----guide-main-branch----------api-docs----------contributing----------chat--) tool:

Currently the bindgen format is unstable enough that these two schema versions must exactly match. You can accomplish this by either updating this binary or the wasm-bindgen dependency in the Rust project.

You can install a particular the binary with:
`cargo install -f wasm-bindgen-cli --version <your version number here>`

```bash
# Install the WASM compilation target (one-time setup)
rustup target add wasm32-unknown-unknown

# Install wasm-bindgen-cli (version must match the wasm-bindgen dependency in Cargo.toml)
cargo install wasm-bindgen-cli --version 0.2.100
```

Then build:

```bash
# Compile to WASM
cargo build --target wasm32-unknown-unknown --release

# Generate JS/TS bindings for browser usage
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm

# Or for Node.js usage
wasm-bindgen --target nodejs --out-dir pkg \
  target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm
```

This generates a `pkg/` directory containing the compiled WASM module and JavaScript/TypeScript bindings that you can import directly.

### CLI tools

```bash
# Install both CLI tools
cargo install --path .

# Or run directly
cargo run --bin generate_keys
cargo run --bin vc_signer
```

---

## Core Concepts

### Credential Structure

A Verifiable Credential is a JSON object with this structure:

```jsonc
{
  // Required: JSON-LD context URLs defining the vocabulary
  "@context": ["https://www.w3.org/ns/credentials/v2"],

  // Optional: unique identifier for this credential
  "id": "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",

  // Required: credential type(s) — must include "VerifiableCredential"
  "type": ["VerifiableCredential", "DeviceCertificate"],

  // Required: who issued this credential (URL or object with "id")
  "issuer": "https://example.com/issuers/device-manufacturer",

  // Required: the actual claims being made
  "credentialSubject": {
    "id": "urn:uuid:device-001",
    "name": "Temperature Sensor A",
    "model": "TS-3000",
  },

  // Optional: when this credential becomes valid (ISO 8601)
  "validFrom": "2024-01-01T00:00:00Z",

  // Optional: when this credential expires (ISO 8601)
  "validUntil": "2030-01-01T00:00:00Z",

  // Optional: JSON Schema reference for validating credentialSubject
  "credentialSchema": {
    "id": "https://example.com/schemas/device.json",
    "type": "JsonSchema",
  },

  // Added by signing — the cryptographic proof
  "proof": {
    "type": "Ed25519Signature2018",
    "proofPurpose": "assertionMethod",
    "proofValue": "base64-encoded-signature...",
  },
}
```

### Ed25519 Keys

This toolkit uses **Ed25519**, a fast and widely-supported digital signature algorithm. Keys are compact (32 bytes each) and signatures are 64 bytes.

- **Private key** (signing key): 32 bytes. Keep this secret. Used by the issuer to sign credentials.
- **Public key** (verifying key): 32 bytes. Share this freely. Used by anyone to verify a credential's authenticity.

Keys are stored as raw binary files (not PEM/DER). The CLI tools generate files named `{timestamp}.priv` and `{timestamp}.pub`.

---

## Usage

### Rust Library

#### Generate a Keypair

```rust
use verifiable_credential_toolkit::generate_keypair;

let keypair = generate_keypair();
// keypair.signing_key:   SigningKey   — keep secret
// keypair.verifying_key: VerifyingKey — distribute to verifiers

// SigningKey and VerifyingKey are distinct types, so a public key can never be
// passed where a private key is expected (and vice versa) — it's a compile error.

// Save the raw 32-byte representations to files
std::fs::write("issuer.priv", keypair.signing_key.to_bytes()).unwrap();
std::fs::write("issuer.pub", keypair.verifying_key.to_bytes()).unwrap();
```

#### Construct a Credential

You can deserialize one from JSON, or build it programmatically with the fluent
builder (which mirrors the `Proof` builder — required fields up front, optional
setters chained, then `.build()`):

```rust
use verifiable_credential_toolkit::{Issuer, UnsignedVerifiableCredential};
use url::Url;
use serde_json::json;

let unsigned_vc = UnsignedVerifiableCredential::builder(
    vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
    vec!["VerifiableCredential".to_string()],
    Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
    json!({ "id": "urn:uuid:device-1", "name": "Sensor A" }),
)
.id(Url::parse("urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df").unwrap())
.build();
```

#### Sign a Credential

```rust
use verifiable_credential_toolkit::{SigningKey, UnsignedVerifiableCredential};

// Load credential from JSON (from a file, API response, etc.)
let vc_json = std::fs::read_to_string("credential.json").unwrap();
let unsigned_vc: UnsignedVerifiableCredential =
    serde_json::from_str(&vc_json).expect("Invalid VC JSON");

// Load private key (validates it is exactly 32 bytes)
let signing_key = SigningKey::from_bytes(&std::fs::read("issuer.priv").unwrap())
    .expect("Invalid private key");

// Sign — produces a VerifiableCredential with a proof attached
let signed_vc = unsigned_vc.sign(&signing_key).expect("Signing failed");

// Serialise and save
let output = serde_json::to_string_pretty(&signed_vc).unwrap();
std::fs::write("credential_signed.json", output).unwrap();
```

#### Verify a Credential

```rust
use verifiable_credential_toolkit::{VerifiableCredential, VerifyingKey};

// Load the signed credential
let vc_json = std::fs::read_to_string("credential_signed.json").unwrap();
let signed_vc: VerifiableCredential =
    serde_json::from_str(&vc_json).expect("Invalid signed VC");

// Load the issuer's public key (validates it is exactly 32 bytes)
let verifying_key = VerifyingKey::from_bytes(&std::fs::read("issuer.pub").unwrap())
    .expect("Invalid public key");

// Verify — checks signature AND validity period (validFrom/validUntil)
match signed_vc.verify(&verifying_key) {
    Ok(()) => println!("Credential is valid and untampered"),
    Err(e) => eprintln!("Verification failed: {}", e),
}
```

#### Sign with JSON Schema Validation

You can validate the `credentialSubject` against a JSON Schema before signing, ensuring the data conforms to an agreed-upon structure:

Schema validation is a separate, composable step: call `validate` with a
`SchemaSource`, then `sign`. This keeps a single signing path regardless of where
the schema comes from.

```rust
use verifiable_credential_toolkit::{SchemaSource, SigningKey, UnsignedVerifiableCredential};

let unsigned_vc: UnsignedVerifiableCredential =
    serde_json::from_str(&std::fs::read_to_string("credential.json").unwrap()).unwrap();
let signing_key = SigningKey::from_bytes(&std::fs::read("issuer.priv").unwrap())
    .expect("Invalid private key");

// Load the schema
let schema: serde_json::Value =
    serde_json::from_str(&std::fs::read_to_string("device_schema.json").unwrap()).unwrap();

// Validate then sign — validate fails if credentialSubject doesn't match the schema
unsigned_vc
    .validate(&SchemaSource::Inline(&schema))
    .expect("Schema validation failed");
let signed_vc = unsigned_vc.sign(&signing_key).expect("Signing failed");
```

`SchemaSource` can also fetch a schema from a URL at validation time (native Rust
only — the `Url` variant is not available in WASM):

```rust
unsigned_vc
    .validate(&SchemaSource::Url("https://example.com/schemas/device.json"))
    .expect("Failed to fetch schema or validate");
let signed_vc = unsigned_vc.sign(&signing_key).expect("Signing failed");
```

#### Customise the Proof

After signing, you can add metadata to the proof using either the builder pattern or direct field access:

```rust
use chrono::{Duration, Utc};
use url::Url;

let mut signed_vc = unsigned_vc.sign(&signing_key).unwrap();

// Builder pattern
signed_vc.proof = signed_vc.proof
    .set_verification_method("did:example:issuer#key-1".to_string())
    .set_crypto_suite("eddsa-rdfc-2022".to_string())
    .set_created(Utc::now())
    .set_expires(Utc::now() + Duration::days(365))
    .set_domain(vec!["https://example.com".to_string()])
    .set_nonce(vec!["abc123".to_string()]);
```

#### Build a Verifiable Presentation

A Verifiable Presentation bundles one or more signed credentials together, for example when a holder wants to present multiple credentials to a verifier at once:

```rust
use verifiable_credential_toolkit::{VerifiableCredential, VerifiablePresentation};
use url::Url;

let vp = VerifiablePresentation {
    context: vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
    id: Some(Url::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap()),
    presentation_type: vec!["VerifiablePresentation".to_string()],
    verifiable_credential: Some(vec![signed_vc]),
    holder: None,
};

let vp_json = serde_json::to_string_pretty(&vp).unwrap();
```

---

### Command-Line Tools

The toolkit includes two CLI tools for quick operations without writing code.

#### `vc_signer` (cargo default-run)

```
A CLI tool for signing Verifiable Credentials

Usage: vc_signer <COMMAND>

Commands:
  sign    Sign a verifiable credential
  verify  Verify a verifiable credential
  help    Print this message or the help of the given subcommand(s)

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

```
Verify a verifiable credential

Usage: vc_signer verify --input-vc <INPUT_VC> --key <KEY>

Options:
  -i, --input-vc <INPUT_VC>  Path to the signed VC JSON file
  -k, --key <KEY>            Path to the public key file
  -h, --help                 Print help
```

**Examples:**

```bash
# Basic signing
cargo run --bin vc_signer -- sign \
  --input-vc unsigned_credential.json \
  --key keys/issuer.priv \
  --output-vc signed_credential.json

# Sign with local schema validation
cargo run --bin vc_signer -- sign \
  --input-vc unsigned_credential.json \
  --key keys/issuer.priv \
  --schema schemas/device.json

# Sign with remote schema validation
cargo run --bin vc_signer -- sign \
  --input-vc unsigned_credential.json \
  --key keys/issuer.priv \
  --schema-url https://example.com/schemas/device.json

# Verify a signed credential
cargo run --bin vc_signer -- verify \
  --input-vc signed_credential.json \
  --key keys/issuer.pub
```

#### `generate_keys`

```
Generates Ed25519 key pairs

Usage: generate_keys [OPTIONS]

Options:
  -o, --output <OUTPUT>  Output directory for the keys [default: .]
  -h, --help             Print help
  -V, --version          Print version
```

**Examples:**

```bash
# Generate a keypair in the current directory
cargo run --bin generate_keys

# Generate a keypair in a specific directory
cargo run --bin generate_keys -- --output ./keys/
```

This creates two raw binary files:

- `{timestamp}.priv` — 32-byte Ed25519 private key
- `{timestamp}.pub` — 32-byte Ed25519 public key

---

### JavaScript / TypeScript (WASM)

The library compiles to WebAssembly for use in browsers and Node.js. TypeScript type definitions are included (see [verifiable_credential_toolkit.d.ts](./verifiable_credential_toolkit.d.ts)).

#### Build the WASM Package

```bash
# Compile to WASM (one command for both targets)
cargo build --target wasm32-unknown-unknown --release

# For browser usage (ES module with init() function)
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm

# For Node.js usage (CommonJS-compatible)
wasm-bindgen --target nodejs --out-dir pkg \
  target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm
```

#### Browser Example

```html
<!DOCTYPE html>
<html>
  <head>
    <title>VC Toolkit Demo</title>
  </head>
  <body>
    <h1>Verifiable Credential Demo</h1>
    <pre id="output"></pre>
    <script type="module">
      import init, {
        sign,
        verify,
        generate_keypair,
      } from "./pkg/verifiable_credential_toolkit.js";

      async function run() {
        // Initialise the WASM module (required for browser target)
        await init();

        // Generate a fresh keypair
        const keypair = generate_keypair();

        // Define a credential
        const unsignedVC = {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential"],
          issuer: "https://example.com/issuers/device-manufacturer",
          credentialSubject: {
            id: "urn:uuid:sensor-001",
            name: "Temperature Sensor Alpha",
          },
        };

        // Sign the credential
        const signedVC = sign(unsignedVC, keypair.signing_key());

        // Verify it
        const isValid = verify(signedVC, keypair.verifying_key());

        document.getElementById("output").textContent =
          `Signed VC:\n${JSON.stringify(signedVC, null, 2)}\n\nValid: ${isValid}`;
      }

      run().catch(console.error);
    </script>
  </body>
</html>
```

#### Node.js Example

```js
import {
  sign,
  verify,
  verify_with_schema_check,
  generate_keypair,
} from "./pkg/verifiable_credential_toolkit.js";

// Generate keys (or load existing ones)
const keypair = generate_keypair();

// Create a credential
const unsignedVC = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",
  type: ["VerifiableCredential", "DeviceCertificate"],
  issuer: "https://example.com/issuers/device-manufacturer",
  validFrom: "2024-01-01T00:00:00Z",
  credentialSchema: {
    id: "https://example.com/schemas/device.json",
    type: "JsonSchema",
  },
  credentialSubject: {
    id: "urn:uuid:device-001",
    name: "Temperature Sensor A",
  },
};

// Sign
const signedVC = sign(unsignedVC, keypair.signing_key());
console.log("Signed VC:", JSON.stringify(signedVC, null, 2));

// Verify (signature + validity period)
const isValid = verify(signedVC, keypair.verifying_key());
console.log("Signature valid:", isValid);

// Verify with schema validation
const schema = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
  },
  required: ["id", "name"],
};

const isValidWithSchema = verify_with_schema_check(
  signedVC,
  keypair.verifying_key(),
  schema,
);
console.log("Valid with schema:", isValidWithSchema);
```

#### TypeScript Types

The package ships with a `.d.ts` file. Key exports:

```typescript
// Key generation
function generate_keypair(): KeyPair;

// Signing and verification
function sign(
  unsigned_vc: UnsignedVerifiableCredential,
  private_key: Uint8Array,
): VerifiableCredential;
function verify(
  signed_vc: VerifiableCredential,
  public_key: Uint8Array,
): boolean;
function verify_with_schema_check(
  signed_vc: VerifiableCredential,
  public_key: Uint8Array,
  schema: any,
): boolean;

// KeyPair class
class KeyPair {
  signing_key(): Uint8Array; // 32-byte private key
  verifying_key(): Uint8Array; // 32-byte public key
}
```

---

## API Reference

### Rust API

| Function / Method                                                                                                | Description                                                                 |
| ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `generate_keypair() → KeyPair`                                                                                   | Generate a new Ed25519 `KeyPair { signing_key, verifying_key }`             |
| `SigningKey::from_bytes(&[u8]) → Result<SigningKey>`                                                             | Parse a 32-byte private key (errors otherwise)                              |
| `VerifyingKey::from_bytes(&[u8]) → Result<VerifyingKey>`                                                         | Parse a 32-byte public key (errors otherwise)                              |
| `UnsignedVerifiableCredential::builder(context, type, issuer, subject) → …Builder`                              | Fluent builder; chain optional setters then `.build()`                      |
| `UnsignedVerifiableCredential::validate(&SchemaSource) → Result<()>`                                             | Validate `credentialSubject` against a `SchemaSource` (`None` / `Inline` / `Url`) |
| `UnsignedVerifiableCredential::sign(&SigningKey) → Result<VerifiableCredential>`                                 | Sign a credential (call `validate` first for schema checks)                 |
| `VerifiableCredential::validate(&SchemaSource) → Result<()>`                                                     | Validate the embedded `credentialSubject` against a `SchemaSource`          |
| `VerifiableCredential::verify(&VerifyingKey) → Result<()>`                                                       | Verify signature and check validity period                                  |
| `VerifiableCredential::to_unsigned() → UnsignedVerifiableCredential`                                             | Strip the proof to get back an unsigned credential                          |

All fallible operations return `Result<_, VcError>` — a typed error enum you can match on (e.g. `VcError::Expired`, `VcError::SchemaMismatch`, `VcError::SignatureVerificationFailed`).

`SigningKey` and `VerifyingKey` are distinct newtypes over 32 bytes, so a private and public key can never be swapped at a call site — the mismatch is a compile error.

`SchemaSource` selects where the JSON Schema comes from: `SchemaSource::None`, `SchemaSource::Inline(&Value)`, or `SchemaSource::Url(&str)` (native only). To validate and sign in one expression: `vc.validate(&schema).and_then(|()| vc.sign(&signing_key))`.

#### Serialization formats (CBOR / Protobuf)

The `bindings` module abstracts wire formats behind the `CredentialCodec` trait. Each format (`bindings::cbor::Cbor`, `bindings::protobuf::Protobuf`) implements it, and two generic helpers work over any codec:

| Function | Description |
| --- | --- |
| `bindings::sign_via::<C>(&[u8], &SigningKey) → Result<Vec<u8>>` | Decode unsigned bytes in format `C`, sign, re-encode |
| `bindings::verify_via::<C>(&[u8], &VerifyingKey) → Result<()>` | Decode signed bytes in format `C` and verify |

The per-format convenience wrappers (`sign_cbor_vc`, `verify_cbor_vc`, `sign_protobuf_vc`, `verify_protobuf_vc`) are thin shims over these.

### WASM/JavaScript API

| Function                                                          | Description                                                              |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `generate_keypair() → KeyPair`                                    | Generate a new Ed25519 keypair                                           |
| `sign(unsignedVC, privateKey) → VerifiableCredential`             | Sign a credential (throws on error)                                      |
| `verify(signedVC, publicKey) → boolean`                           | Verify a signed credential                                               |
| `verify_with_schema_check(signedVC, publicKey, schema) → boolean` | Verify with JSON Schema validation                                       |
| `sign_cbor_vc(unsignedBytes, privateKey) → Uint8Array`            | Sign a CBOR-encoded credential                                           |
| `verify_cbor_vc(signedBytes, publicKey) → boolean`                | Verify a CBOR-encoded credential                                         |
| `sign_protobuf_vc(unsignedBytes, privateKey) → Uint8Array`        | Sign a Protobuf-encoded credential                                       |
| `verify_protobuf_vc(signedBytes, publicKey) → boolean`            | Verify a Protobuf-encoded credential                                     |
| `normalize_object(input) → any`                                   | Remove `undefined`/`null` values from JS objects (useful before signing) |

TypeScript types live in [`verifiable_credential_toolkit.d.ts`](./verifiable_credential_toolkit.d.ts). Keys use branded types (`SigningKey` / `VerifyingKey`) so a public and private key can't be swapped at a call site — `KeyPair.signing_key()` / `.verifying_key()` return the right brand, and raw bytes are branded with an assertion (`bytes as SigningKey`).

---

## JSON Schema Validation

You can enforce a structure on `credentialSubject` using [JSON Schema](https://json-schema.org/). This is useful when multiple parties agree on what fields a credential should contain.

Example schema for a device credential:

```json
{
  "title": "Device",
  "description": "Schema for a device credential subject",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "description": "Unique identifier for the device"
    },
    "name": {
      "type": "string",
      "description": "Human-readable device name"
    },
    "model": {
      "type": "string",
      "description": "Device model number"
    }
  },
  "required": ["id", "name"]
}
```

When you call `validate` with a `SchemaSource` (in Rust) or use `verify_with_schema_check` (in WASM/JavaScript), the `credentialSubject` is validated against this schema. If it doesn't match the required structure, the operation returns an error.

---

## Examples

Working examples are included in the repository:

| Directory                                                    | Description                                          |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| [`wasm_js_example_usage/`](./wasm_js_example_usage/)         | Browser-based signing and verification using WASM    |
| [`wasm_nodejs_example_usage/`](./wasm_nodejs_example_usage/) | Node.js signing, verification, and schema validation |
| [`examples/`](./examples/)                                   | Rust examples (run with `cargo run --example`)       |

Both examples are written in TypeScript and exercise the full WASM API:
sign/verify, tamper + wrong-key rejection, JSON-Schema validation, validity
periods, the `normalize_*` helpers, and the CBOR + Protobuf bindings. The
CBOR/Protobuf sections do a full round-trip entirely in JS — encoding the
credential object to bytes, decoding it back, signing, and verifying — so no
pre-encoded fixtures are needed. The Node example self-checks every result (and
exits non-zero on failure); the browser example renders each result on the page.

### Running the Node.js Example

```bash
cd wasm_nodejs_example_usage

# Builds the WASM, generates Node.js bindings, and writes pkg/package.json.
# wasm-bindgen's `nodejs` target emits CommonJS, but this dir is an ES module
# ("type": "module"), so pkg/ needs its own package.json declaring
# "type": "commonjs". `npm run build` does all of this.
npm run build

# Run it (Node >= 22 runs the .ts directly by stripping the types)
npm start          # or: node index.ts
```

If you build by hand instead of `npm run build`, remember the final step:

```bash
echo '{"type":"commonjs"}' > wasm_nodejs_example_usage/pkg/package.json
```

### Running the Browser Example

```bash
cd wasm_js_example_usage

npm install        # one-time: installs the TypeScript compiler
npm run build      # builds WASM (--target web) and compiles index.ts -> index.js
npm run serve      # python3 -m http.server 8080
# Open http://localhost:8080 in your browser; results render on the page.
```

### Running the Rust Examples

```bash
# End-to-end: generate keys, sign, verify, and inspect
cargo run --example full_workflow

# Signing with JSON Schema validation
cargo run --example schema_validation
```

---

## Verifiable Presentations

A **Verifiable Presentation** (VP) is a wrapper that bundles one or more Verifiable Credentials for transmission to a verifier. Use cases include:

- A device presenting both a manufacturer certificate and a calibration certificate.
- A user presenting identity and access credentials together.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiablePresentation"],
  "verifiableCredential": [
    {
      /* signed VC 1 */
    },
    {
      /* signed VC 2 */
    }
  ],
  "holder": "did:example:holder-123"
}
```

---

## Security Considerations

- **Protect private keys.** Anyone with access to a private key can forge credentials. Store them securely (e.g. hardware security modules, encrypted storage).
- **Distribute public keys via trusted channels.** Verifiers must be confident a public key genuinely belongs to the claimed issuer.
- **Set validity periods.** Use `validFrom` and `validUntil` to limit the window during which a credential is accepted.
- **Use schema validation** when you need to enforce a specific data structure on credentials.
- **Key rotation.** Periodically generate new keypairs and re-issue credentials as needed.

---

## License

Apache-2.0 — see [Cargo.toml](./Cargo.toml) for details.
