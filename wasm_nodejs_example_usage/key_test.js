// index.js
import { generate_keypair } from "./pkg/verifiable_credential_toolkit.js";

async function run() {
  let keypair = generate_keypair();

  console.log("Private key:", keypair.signing_key());
  console.log("Public key:", keypair.verifying_key());
}

run();
