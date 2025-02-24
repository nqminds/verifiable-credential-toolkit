import fs from "fs";

// Reads a key file and returns a Uint8Array.
// Adjust the encoding if your key file is not raw binary.
function loadKey(filePath) {
  // Read file as a Buffer (raw binary)
  const buffer = fs.readFileSync(filePath);
  return new Uint8Array(buffer);
}

// If your keys are stored as base64 strings, you can do:
// const base64Data = fs.readFileSync(filePath, { encoding: "utf8" });
// const buffer = Buffer.from(base64Data, "base64");
// return new Uint8Array(buffer);

const privateKeyArray = loadKey("./tests/test_data/keys/key.priv");
const publicKeyArray = loadKey("./tests/test_data/keys/key.pub");

console.log("Private Key:", privateKeyArray);
console.log("Public Key:", publicKeyArray);

// Now you can pass these Uint8Arrays to your WASM sign and verify functions.
