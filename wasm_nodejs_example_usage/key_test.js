// Example: Generate an Ed25519 keypair using the WASM module
//
// Prerequisites:
//   1. cargo build --target wasm32-unknown-unknown --release
//   2. wasm-bindgen --target nodejs --out-dir wasm_nodejs_example_usage/pkg target/wasm32-unknown-unknown/release/verifiable_credential_toolkit.wasm
//   3. Run: node key_test.js

import { generate_keypair } from "./pkg/verifiable_credential_toolkit.js";

const keypair = generate_keypair();

console.log("=== Ed25519 Keypair ===\n");
console.log("Private (signing) key: ", keypair.signing_key());
console.log("Public (verifying) key:", keypair.verifying_key());
console.log(`\nKey sizes: ${keypair.signing_key().length} bytes each`);
