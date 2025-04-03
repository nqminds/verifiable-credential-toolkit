// index.js
import {
  sign,
  verify,
  verify_with_schema_check,
} from "./pkg/verifiable_credential_toolkit.js";

async function run() {
  // Example Unsigned Verifiable Credential (VC)
  const unsignedVC = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",
    type: ["VerifiableCredential", "ExampleVerifiableCredential"],
    issuer: "https://www.example.com/",
    validFrom: "2024-08-22T13:53:32.295644150Z",
    credentialSchema: {
      id: "https://www.example.com/foo.json",
      type: "JsonSchema",
    },
    credentialSubject: {
      name: "HenryTrustPhone",
      id: "HenryTrustPhone-id",
    },
  };

  const schema = {
    description: "A device",
    properties: {
      id: {
        description: "id of the device",
        type: "string",
      },
      name: {
        description: "user friendly name of the device",
        type: "string",
      },
    },
    required: ["id"],
    title: "device",
    type: "object",
  };

  // Dummy private key (32 bytes) for testing.
  const privateKeyArray = new Uint8Array([
    249, 36, 149, 249, 249, 117, 133, 209, 234, 131, 132, 144, 15, 129, 114,
    114, 244, 234, 241, 239, 198, 73, 72, 185, 156, 200, 237, 170, 2, 142, 41,
    36,
  ]);

  // Dummy public key (32 bytes) for testing.
  const publicKeyArray = new Uint8Array([
    158, 252, 71, 183, 71, 40, 45, 125, 208, 153, 210, 175, 216, 211, 29, 93,
    55, 89, 128, 135, 108, 220, 209, 142, 148, 55, 66, 57, 157, 249, 8, 204,
  ]);

  try {
    // Sign the unsigned VC
    const signedVC = sign(unsignedVC, privateKeyArray);
    console.log("Signed VC:", signedVC);

    // Verify the signed VC
    const verificationResult = verify_with_schema_check(
      signedVC,
      publicKeyArray,
      schema
    );
    console.log("Verification result:", verificationResult);
  } catch (err) {
    console.error("Error during signing or verifying:", err);
  }
}

run();
