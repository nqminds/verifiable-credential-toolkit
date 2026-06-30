# Verifiable Credential Toolkit

A Rust library (with WASM/JavaScript bindings) for creating, signing, and verifying [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/). It signs with Ed25519 or post-quantum ML-DSA (FIPS 204) to ensure credentials are tamper-proof and can be independently verified.

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
    Algorithm, UnsignedVerifiableCredential, generate_keypair,
};

// 1. Generate a keypair (signing_key: SigningKey, verifying_key: VerifyingKey).
//    The algorithm travels with each key; pass ML-DSA-44/65/87 here for post-quantum.
let keypair = generate_keypair(Algorithm::Ed25519);

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
verifiable-credential-toolkit = "0.7"
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
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z-multibase-encoded-signature...",
  },
}
```

### Signature algorithms

The toolkit signs and verifies with these algorithms, selected via the [`Algorithm`] enum:

| Algorithm | `Algorithm` variant | Private key | Public key | `cryptosuite` |
|---|---|---:|---:|---|
| Ed25519 (EdDSA) | `Ed25519` | 32 | 32 | `eddsa-jcs-2022` |
| ML-DSA-44 (FIPS 204, cat. 2) | `MlDsa44` | 2560 | 1312 | `mldsa44-jcs-2025` |
| ML-DSA-65 (FIPS 204, cat. 3) | `MlDsa65` | 4032 | 1952 | `mldsa65-jcs-2025` |
| ML-DSA-87 (FIPS 204, cat. 5) | `MlDsa87` | 4896 | 2592 | `mldsa87-jcs-2025` |

ML-DSA (the NIST post-quantum signature standard) is provided via the `ml-dsa` crate, and is just another `Algorithm` — there is no separate ML-DSA API. The typed `SigningKey` / `VerifyingKey` carry their algorithm, are length-checked at construction, and pair with the same `sign` / `verify` used for Ed25519 (so the algorithm can't disagree with the key, and `verify` rejects a proof whose cryptosuite names a different algorithm):

```rust
let keypair = generate_keypair(Algorithm::MlDsa65);   // typed pair, algorithm carried by the key
let signed = unsigned.sign(&keypair.signing_key)?;
signed.verify(&keypair.verifying_key)?;
```

For HSM, cross-language, or wasm interop where keys are just bytes, use the raw-byte path: `generate_keypair_bytes(Algorithm)` plus `sign_with_algorithm` / `verify_with_algorithm` / `verify_auto`.

```rust
let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);
let signed = unsigned.sign_with_algorithm(Algorithm::MlDsa65, &private_key)?;
signed.verify_auto(&public_key)?;            // reads the algorithm from proof.cryptosuite
```

`verify_auto` dispatches on the proof's `cryptosuite`; `verify_with_algorithm` takes an explicit algorithm; `verify` reads it from the typed key. Ed25519 keys can still be loaded as raw 32-byte files (`{timestamp}.priv` / `.pub` from the CLI tools) via `SigningKey::new(Algorithm::Ed25519, &bytes)`.

> ⚠️ **Provisional ML-DSA cryptosuite identifiers.** The W3C `vc-di-mldsa` cryptosuite is still a Working Draft with no finalized identifier, multikey codec, or canonicalization choice. The `mldsa{44,65,87}-jcs-2025` strings above are a **bilateral convention** for closed deployments (e.g. NATO IC 2026 partners) — signing and verifying parties must agree on them out of band and document them; they are not interoperable with arbitrary third-party verifiers until the standard finalizes.

### Bring-your-own / external signatures

If you compute a signature outside the crate (e.g. in an HSM), call [`signing_payload`] to get the exact JCS bytes to sign, then wrap the result with `Proof::new_data_integrity(cryptosuite, proof_value)` (or `Proof::set_proof_value`) and `VerifiableCredential::from_parts(unsigned, proof)`. The `proofValue` is the **multibase (base58btc)** encoding of the raw signature bytes — i.e. `multibase::encode(Base58Btc, signature)`, a `z`-prefixed string.

### Canonical signing

The signature is computed over the credential serialized with **JCS (JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785))**, used by every cryptosuite above. Canonicalization sorts object keys and normalizes number formatting, so the signed bytes are independent of field ordering. This means a signature stays valid across a serialize/deserialize round-trip and across encodings (JSON, CBOR, Protobuf) — the proof is over the credential's canonical form, not the wire bytes. The emitted proof is a `DataIntegrityProof` whose `cryptosuite` matches the signing algorithm, with the signature stored as a multibase (base58btc) `proofValue`.

Every algorithm works across all three formats. For CBOR and Protobuf, sign with `Cbor::sign(bytes, algorithm, private_key)` / `Protobuf::sign(...)` and verify with `Cbor::verify_auto(bytes, public_key)` (reads the cryptosuite) or `Cbor::verify(bytes, algorithm, public_key)`. Because the signature is over the format-independent JCS form, a credential signed in one format verifies in any other.

ML-DSA signing is **hedged** (FIPS 204's randomized variant), so ML-DSA signatures are non-deterministic; Ed25519 signatures remain deterministic.

> **Compatibility note:** signatures are not interchangeable across encodings of the `proofValue`. 0.5.x signed over non-canonical JSON; 0.6.x used a base64 `proofValue`; **0.7.0** uses a **multibase** `proofValue`. Credentials issued by earlier versions must be re-signed. 0.7.0 is also breaking in that `verify` now rejects an unknown or missing `cryptosuite`, and `VcError::SignatureVerificationFailed` is a unit variant.

---

## Usage

### Rust Library

#### Generate a Keypair

```rust
use verifiable_credential_toolkit::{generate_keypair, Algorithm};

let keypair = generate_keypair(Algorithm::Ed25519);
// keypair.signing_key:   SigningKey   — keep secret
// keypair.verifying_key: VerifyingKey — distribute to verifiers

// SigningKey and VerifyingKey are distinct types, so a public key can never be
// passed where a private key is expected (and vice versa) — it's a compile error.
// Each key carries its Algorithm, so the same sign/verify works for any algorithm.

// Save the raw key bytes to files
std::fs::write("issuer.priv", keypair.signing_key.as_bytes()).unwrap();
std::fs::write("issuer.pub", keypair.verifying_key.as_bytes()).unwrap();
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
use verifiable_credential_toolkit::{Algorithm, SigningKey, UnsignedVerifiableCredential};

// Load credential from JSON (from a file, API response, etc.)
let vc_json = std::fs::read_to_string("credential.json").unwrap();
let unsigned_vc: UnsignedVerifiableCredential =
    serde_json::from_str(&vc_json).expect("Invalid VC JSON");

// Load private key (validates the length matches the algorithm)
let signing_key = SigningKey::new(Algorithm::Ed25519, &std::fs::read("issuer.priv").unwrap())
    .expect("Invalid private key");

// Sign — produces a VerifiableCredential with a proof attached
let signed_vc = unsigned_vc.sign(&signing_key).expect("Signing failed");

// Serialise and save
let output = serde_json::to_string_pretty(&signed_vc).unwrap();
std::fs::write("credential_signed.json", output).unwrap();
```

#### Verify a Credential

```rust
use verifiable_credential_toolkit::{Algorithm, VerifiableCredential, VerifyingKey};

// Load the signed credential
let vc_json = std::fs::read_to_string("credential_signed.json").unwrap();
let signed_vc: VerifiableCredential =
    serde_json::from_str(&vc_json).expect("Invalid signed VC");

// Load the issuer's public key (validates the length matches the algorithm)
let verifying_key = VerifyingKey::new(Algorithm::Ed25519, &std::fs::read("issuer.pub").unwrap())
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
use verifiable_credential_toolkit::{Algorithm, SchemaSource, SigningKey, UnsignedVerifiableCredential};

let unsigned_vc: UnsignedVerifiableCredential =
    serde_json::from_str(&std::fs::read_to_string("credential.json").unwrap()).unwrap();
let signing_key = SigningKey::new(Algorithm::Ed25519, &std::fs::read("issuer.priv").unwrap())
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
    .set_crypto_suite("eddsa-jcs-2022".to_string())
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
| `generate_keypair(Algorithm) → KeyPair`                                                                          | Generate a `KeyPair { signing_key, verifying_key }` for any algorithm       |
| `generate_keypair_bytes(Algorithm) → (Vec<u8>, Vec<u8>)`                                                         | Generate raw `(private, public)` key bytes (HSM / wasm / cross-language interop) |
| `SigningKey::new(Algorithm, &[u8]) → Result<SigningKey>`                                                         | Wrap private-key bytes, length-checked against the algorithm                |
| `VerifyingKey::new(Algorithm, &[u8]) → Result<VerifyingKey>`                                                     | Wrap public-key bytes, length-checked against the algorithm                 |
| `UnsignedVerifiableCredential::builder(context, type, issuer, subject) → …Builder`                              | Fluent builder; chain optional setters then `.build()`                      |
| `UnsignedVerifiableCredential::validate(&SchemaSource) → Result<()>`                                             | Validate `credentialSubject` against a `SchemaSource` (`None` / `Inline` / `Url`) |
| `UnsignedVerifiableCredential::sign(&SigningKey) → Result<VerifiableCredential>`                                 | Sign a credential; algorithm read from the key (call `validate` first for schema checks) |
| `UnsignedVerifiableCredential::sign_with_algorithm(Algorithm, &[u8]) → Result<VerifiableCredential>`             | Sign with an explicit algorithm and raw private-key bytes                   |
| `VerifiableCredential::validate(&SchemaSource) → Result<()>`                                                     | Validate the embedded `credentialSubject` against a `SchemaSource`          |
| `VerifiableCredential::verify(&VerifyingKey) → Result<()>`                                                       | Verify signature + validity period; checks the proof's cryptosuite matches the key's algorithm |
| `VerifiableCredential::verify_auto(&[u8]) → Result<()>` / `verify_with_algorithm(Algorithm, &[u8])`              | Verify from raw public-key bytes, dispatching on the proof's cryptosuite (or an explicit algorithm) |
| `VerifiableCredential::to_unsigned() → UnsignedVerifiableCredential`                                             | Strip the proof to get back an unsigned credential                          |

All fallible operations return `Result<_, VcError>` — a typed error enum you can match on (e.g. `VcError::Expired`, `VcError::SchemaMismatch`, `VcError::SignatureVerificationFailed`).

`SigningKey` and `VerifyingKey` are distinct types that each carry their `Algorithm` (Ed25519 or an ML-DSA parameter set), so a private and public key can never be swapped at a call site — the mismatch is a compile error — and `sign` / `verify` read the algorithm from the key.

`SchemaSource` selects where the JSON Schema comes from: `SchemaSource::None`, `SchemaSource::Inline(&Value)`, or `SchemaSource::Url(&str)` (native only). To validate and sign in one expression: `vc.validate(&schema).and_then(|()| vc.sign(&signing_key))`.

#### Serialization formats (CBOR / Protobuf)

The `bindings` module abstracts wire formats behind the `CredentialCodec` trait. Each format (`bindings::cbor::Cbor`, `bindings::protobuf::Protobuf`) implements four bytes↔domain conversions; the sign/verify pipeline is provided once as default methods on the trait, so the format *type* is the entry point — there are no per-format free functions to learn. Because the signature is over the format-independent JCS canonical form, a credential signed in one format verifies in any other.

| Method (on `Cbor` / `Protobuf`) | Description |
| --- | --- |
| `C::encode_unsigned(&Unsigned…) → Result<Vec<u8>>` / `C::encode_signed(&…) → Result<Vec<u8>>` | Encode to this format's bytes |
| `C::decode_unsigned(&[u8])` / `C::decode_signed(&[u8])` | Decode from this format's bytes |
| `C::sign(&[u8], Algorithm, &[u8]) → Result<Vec<u8>>` | Decode unsigned bytes, sign with any cryptosuite, re-encode |
| `C::verify(&[u8], Algorithm, &[u8]) → Result<()>` | Decode signed bytes and verify with an explicit algorithm |
| `C::verify_auto(&[u8], &[u8]) → Result<()>` | Verify, reading the algorithm from the proof's `cryptosuite` |

```rust
let signed = Cbor::sign(&unsigned_cbor, Algorithm::MlDsa65, &private_key)?;
Cbor::verify_auto(&signed, &public_key)?;
```

### WASM/JavaScript API

| Function                                                          | Description                                                              |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `generate_keypair() → KeyPair`                                    | Generate a new Ed25519 keypair                                           |
| `generate_keypair_for(algorithm) → KeyPair`                       | Generate a keypair for any algorithm label (`Ed25519`, `ML-DSA-44/65/87`) |
| `sign(unsignedVC, privateKey) → VerifiableCredential`             | Sign a credential with Ed25519 (throws on error)                         |
| `verify(signedVC, publicKey) → boolean`                           | Verify an Ed25519 signed credential                                      |
| `sign_with_algorithm(unsignedVC, algorithm, privateKey) → VerifiableCredential` | Sign with any algorithm and raw key bytes              |
| `verify_with_algorithm(signedVC, algorithm, publicKey) → boolean` | Verify with an explicit algorithm                                        |
| `verify_auto(signedVC, publicKey) → boolean`                      | Verify, reading the algorithm from the proof's `cryptosuite`             |
| `verify_with_schema_check(signedVC, publicKey, schema) → boolean` | Verify (Ed25519) with JSON Schema validation                             |
| `sign_cbor_vc(unsignedBytes, privateKey) → Uint8Array`            | Sign a CBOR-encoded credential with Ed25519                              |
| `verify_cbor_vc(signedBytes, publicKey) → boolean`                | Verify a CBOR-encoded Ed25519 credential                                 |
| `sign_cbor_vc_with_algorithm(unsignedBytes, algorithm, privateKey) → Uint8Array` | Sign CBOR bytes with any algorithm                      |
| `verify_cbor_vc_auto(signedBytes, publicKey) → boolean`           | Verify CBOR bytes, reading the algorithm from the proof                  |
| `sign_protobuf_vc(unsignedBytes, privateKey) → Uint8Array`        | Sign a Protobuf-encoded credential with Ed25519                          |
| `verify_protobuf_vc(signedBytes, publicKey) → boolean`            | Verify a Protobuf-encoded Ed25519 credential                             |
| `sign_protobuf_vc_with_algorithm(unsignedBytes, algorithm, privateKey) → Uint8Array` | Sign Protobuf bytes with any algorithm              |
| `verify_protobuf_vc_auto(signedBytes, publicKey) → boolean`       | Verify Protobuf bytes, reading the algorithm from the proof              |
| `normalize_object(input) → any`                                   | Recursively strip `undefined` values from a JS object/array (`null` is preserved); useful before signing |

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
