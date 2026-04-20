// Browser example: Sign and verify a Verifiable Credential using WASM
//
// Prerequisites:
//   1. cargo build --target wasm32-unknown-unknown --release
//   2. wasm-bindgen --target web --out-dir wasm_js_example_usage/pkg target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm
//   3. cd wasm_js_example_usage && python3 -m http.server 8080
//   4. Open http://localhost:8080 in your browser

import init, { sign, verify, generate_keypair } from "./pkg/verifiable_credential_toolkit.js";

async function run() {
  // Initialise the WASM module (required once before calling any functions)
  await init();

  const output = document.getElementById("output");
  const log = (msg) => {
    console.log(msg);
    output.innerHTML += `<pre>${typeof msg === "string" ? msg : JSON.stringify(msg, null, 2)}</pre>`;
  };

  // ── Step 1: Generate an Ed25519 keypair ──────────────────────────────
  log("Step 1: Generating Ed25519 keypair…");
  const keypair = generate_keypair();
  log(`  Private key: ${keypair.signing_key().length} bytes`);
  log(`  Public key:  ${keypair.verifying_key().length} bytes`);

  // ── Step 2: Define an unsigned Verifiable Credential ─────────────────
  log("\nStep 2: Creating unsigned Verifiable Credential…");
  const unsignedVC = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    type: ["VerifiableCredential", "DeviceCertificate"],
    issuer: "https://example.com/issuers/sensor-manufacturer",
    credentialSubject: {
      id: "urn:uuid:sensor-001",
      name: "Temperature Sensor Alpha",
      model: "TS-3000",
    },
  };
  log(unsignedVC);

  try {
    // ── Step 3: Sign the credential ────────────────────────────────────
    log("\nStep 3: Signing…");
    const signedVC = sign(unsignedVC, keypair.signing_key());
    log(signedVC);

    // ── Step 4: Verify the credential ──────────────────────────────────
    log("\nStep 4: Verifying…");
    const isValid = verify(signedVC, keypair.verifying_key());
    log(`<span class="status ${isValid ? "ok" : "fail"}">Verification result: ${isValid}</span>`);

    // ── Step 5: Demonstrate tamper detection ────────────────────────────
    log("\nStep 5: Tamper detection — modifying the credential and re-verifying…");
    const tamperedVC = JSON.parse(JSON.stringify(signedVC));
    tamperedVC.credentialSubject.name = "TAMPERED NAME";
    const isTamperedValid = verify(tamperedVC, keypair.verifying_key());
    log(`<span class="status ${!isTamperedValid ? "ok" : "fail"}">Tampered credential valid: ${isTamperedValid} (expected: false)</span>`);
  } catch (err) {
    log(`Error: ${err.message}`);
    console.error(err);
  }
}

run();
