// index.js
import init, { sign, verify } from "./pkg/verifiable_credential_toolkit.js";

async function run() {
  // Initialize the WASM module
  await init();

  // Example Unsigned Verifiable Credential (VC)
  const unsignedVC = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.com/credentials/3732",
    "type": ["VerifiableCredential"],
    "issuer": "https://example.com/issuers/14",
    "credentialSubject": { "id": "did:example:abcdef" }
  };

  // Dummy private key (32 bytes) for testing.
  // In a real scenario, use a proper cryptographic seed.
  const privateKeyArray = new Uint8Array([
    249,  36, 149, 249, 249, 117, 133,
    209, 234, 131, 132, 144,  15, 129,
    114, 114, 244, 234, 241, 239, 198,
     73,  72, 185, 156, 200, 237, 170,
      2, 142,  41,  36
  ]);

  // Dummy public key (32 bytes) for testing.
  // This should correspond to the private key (if generated properly).
  const publicKeyArray = new Uint8Array([
    158, 252,  71, 183,  71,  40,  45, 125,
    208, 153, 210, 175, 216, 211,  29,  93,
     55,  89, 128, 135, 108, 220, 209, 142,
    148,  55,  66,  57, 157, 249,   8, 204
  ]);


  try {
    // Sign the unsigned VC
    const signedVC = sign(unsignedVC, privateKeyArray);
    console.log("Signed VC:", signedVC);

    // Verify the signed VC
    const verificationResult = verify(signedVC, publicKeyArray);
    console.log("Verification result:", verificationResult);
  } catch (err) {
    console.error("Error during signing or verifying:", err);
  }
}

run();
