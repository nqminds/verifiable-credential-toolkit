// Node.js example: Sign and verify a Verifiable Credential with schema validation
//
// Prerequisites:
//   1. cargo build --target wasm32-unknown-unknown --release
//   2. wasm-bindgen --target nodejs --out-dir wasm_nodejs_example_usage/pkg target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm
//   3. Run: node index.js

import {
  sign,
  verify,
  verify_with_schema_check,
  generate_keypair,
} from "./pkg/verifiable_credential_toolkit.js";

async function run() {
  // ── Step 1: Generate an Ed25519 keypair ──────────────────────────────
  console.log("=== Step 1: Generate keypair ===\n");
  const keypair = generate_keypair();
  console.log(`  Private key: ${keypair.signing_key().length} bytes`);
  console.log(`  Public key:  ${keypair.verifying_key().length} bytes\n`);

  // ── Step 2: Define a credential ──────────────────────────────────────
  console.log("=== Step 2: Create unsigned Verifiable Credential ===\n");
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
  console.log(JSON.stringify(unsignedVC, null, 2), "\n");

  // ── Step 3: Sign the credential ──────────────────────────────────────
  console.log("=== Step 3: Sign the credential ===\n");
  const signedVC = sign(unsignedVC, keypair.signing_key());
  console.log("Signed VC:", JSON.stringify(signedVC, null, 2), "\n");

  // ── Step 4: Verify (signature only) ──────────────────────────────────
  console.log("=== Step 4: Verify signature ===\n");
  const isValid = verify(signedVC, keypair.verifying_key());
  console.log(`  Signature valid: ${isValid}\n`);

  // ── Step 5: Verify with JSON Schema validation ───────────────────────
  // The schema defines what fields the credentialSubject must contain.
  // This is useful when multiple parties agree on a data format.
  console.log("=== Step 5: Verify with schema ===\n");
  const schema = {
    title: "Device",
    description: "Schema for a device credential subject",
    type: "object",
    properties: {
      id: { type: "string", description: "Unique device identifier" },
      name: { type: "string", description: "Human-readable device name" },
    },
    required: ["id", "name"],
  };
  console.log("Schema:", JSON.stringify(schema, null, 2));

  const isValidWithSchema = verify_with_schema_check(
    signedVC,
    keypair.verifying_key(),
    schema,
  );
  console.log(`  Valid with schema: ${isValidWithSchema}\n`);

  // ── Step 6: Demonstrate schema rejection ─────────────────────────────
  console.log("=== Step 6: Schema rejection (stricter schema) ===\n");
  const stricterSchema = {
    type: "object",
    properties: {
      id: { type: "string" },
      name: { type: "string" },
      model: { type: "string" },
    },
    required: ["id", "name", "model"], // "model" is missing from the credential
  };

  const isValidStrict = verify_with_schema_check(
    signedVC,
    keypair.verifying_key(),
    stricterSchema,
  );
  console.log(`  Valid with stricter schema: ${isValidStrict} (expected: false)\n`);

  console.log("=== Done! ===");
}

run().catch(console.error);
