// Browser example — exercises the full WASM API surface (including the CBOR and
// Protobuf byte bindings) and reports each result on the page.
//
// The CBOR / Protobuf sections fetch unsigned-VC byte fixtures (encoded by the
// Rust side) over HTTP, so they require the dev server — opening the file
// directly via file:// will fail the fetch.
//
// Build & serve (from this directory):
//   npm install          # one-time: installs the TypeScript compiler
//   npm run build        # builds WASM (--target web) and compiles index.ts
//   npm run serve        # python3 -m http.server 8080
//   open http://localhost:8080

import init, {
  generate_keypair,
  sign,
  verify,
  verify_with_schema_check,
  normalize_object,
  normalize_and_stringify,
  sign_cbor_vc,
  verify_cbor_vc,
  sign_protobuf_vc,
  verify_protobuf_vc,
} from "./pkg/verifiable_credential_toolkit.js";
// Data-model types from the hand-maintained root declaration file (erased at runtime).
import type {
  UnsignedVerifiableCredential,
  VerifiableCredential,
} from "../verifiable_credential_toolkit";

const output = document.getElementById("output") as HTMLElement;

function check(label: string, ok: boolean): void {
  const cls = ok ? "ok" : "fail";
  const mark = ok ? "✓" : "✗";
  output.innerHTML += `<div class="status ${cls}">${mark} ${label}</div>`;
  console.log(`${mark} ${label}`);
}
function section(title: string): void {
  output.innerHTML += `<h2>${title}</h2>`;
}
function show(value: unknown): void {
  output.innerHTML += `<pre>${JSON.stringify(value, null, 2)}</pre>`;
}
async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path);
  return new Uint8Array(await response.arrayBuffer());
}
function flipMiddleByte(bytes: Uint8Array): Uint8Array {
  const copy = bytes.slice();
  copy[Math.floor(copy.length / 2)] ^= 0x01;
  return copy;
}

const baseVC: UnsignedVerifiableCredential = {
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

async function run(): Promise<void> {
  // Initialise the WASM module (required once before calling any function).
  await init();
  output.innerHTML = "";

  // ── 1. Key generation ───────────────────────────────────────────────────
  section("1. Key generation");
  const keypair = generate_keypair();
  const signingKey = keypair.signing_key();
  const verifyingKey = keypair.verifying_key();
  check("signing key is 32 bytes", signingKey.length === 32);
  check("verifying key is 32 bytes", verifyingKey.length === 32);

  // ── 2. Sign and verify ──────────────────────────────────────────────────
  section("2. Sign and verify");
  const signed: VerifiableCredential = sign(baseVC, signingKey);
  show(signed);
  check("verify succeeds with the right key", verify(signed, verifyingKey) === true);

  // ── 3. Tamper detection ─────────────────────────────────────────────────
  section("3. Tamper detection");
  const tampered: VerifiableCredential = JSON.parse(JSON.stringify(signed));
  tampered.credentialSubject.name = "TAMPERED NAME";
  check("tampered credential is rejected", verify(tampered, verifyingKey) === false);

  // ── 4. Wrong key ────────────────────────────────────────────────────────
  section("4. Wrong verifying key");
  const other = generate_keypair();
  check("a different public key is rejected", verify(signed, other.verifying_key()) === false);

  // ── 5. JSON Schema validation ───────────────────────────────────────────
  section("5. JSON Schema validation");
  const schema = {
    type: "object",
    properties: { id: { type: "string" }, name: { type: "string" } },
    required: ["id", "name"],
  };
  check(
    "matching subject passes",
    verify_with_schema_check(signed, verifyingKey, schema) === true,
  );
  const strictSchema = { type: "object", required: ["id", "name", "serialNumber"] };
  check(
    "missing required field fails",
    verify_with_schema_check(signed, verifyingKey, strictSchema) === false,
  );

  // ── 6. Validity period ──────────────────────────────────────────────────
  section("6. Validity period");
  const expired = sign({ ...baseVC, validUntil: "2000-01-01T00:00:00Z" }, signingKey);
  check("expired credential is rejected", verify(expired, verifyingKey) === false);
  const notYetValid = sign({ ...baseVC, validFrom: "2999-01-01T00:00:00Z" }, signingKey);
  check("not-yet-valid credential is rejected", verify(notYetValid, verifyingKey) === false);

  // ── 7. normalize helpers ────────────────────────────────────────────────
  section("7. normalize_object / normalize_and_stringify");
  const messy = { a: 1, b: undefined, c: null, d: { e: undefined, f: 2 } };
  const normalized = normalize_object(messy) as Record<string, unknown>;
  check("undefined keys are stripped", !("b" in normalized) && "a" in normalized);
  check(
    "normalize_and_stringify returns JSON text",
    normalize_and_stringify(messy).includes('"a":1'),
  );

  // ── 8. CBOR bindings ──────────────────────────────────────────────────────
  // The unsigned credential is fetched as a fixture encoded by the Rust side
  // (google.protobuf.Value / canonical CBOR are impractical to hand-encode here).
  section("8. CBOR bindings");
  const unsignedCbor = await fetchBytes("./fixtures/unsigned_vc.cbor");
  const signedCbor = sign_cbor_vc(unsignedCbor, signingKey);
  check("sign_cbor_vc returns bytes", signedCbor instanceof Uint8Array && signedCbor.length > 0);
  check("verify_cbor_vc succeeds", verify_cbor_vc(signedCbor, verifyingKey) === true);
  let cborRejected = false;
  try {
    verify_cbor_vc(flipMiddleByte(signedCbor), verifyingKey);
  } catch {
    cborRejected = true;
  }
  check("tampered CBOR is rejected", cborRejected);

  // ── 9. Protobuf bindings ──────────────────────────────────────────────────
  section("9. Protobuf bindings");
  const unsignedPb = await fetchBytes("./fixtures/unsigned_vc.pb");
  const signedPb = sign_protobuf_vc(unsignedPb, signingKey);
  check("sign_protobuf_vc returns bytes", signedPb instanceof Uint8Array && signedPb.length > 0);
  check("verify_protobuf_vc succeeds", verify_protobuf_vc(signedPb, verifyingKey) === true);
  let pbRejected = false;
  try {
    verify_protobuf_vc(flipMiddleByte(signedPb), verifyingKey);
  } catch {
    pbRejected = true;
  }
  check("tampered Protobuf is rejected", pbRejected);
}

run().catch((err) => {
  output.innerHTML += `<div class="status fail">Error: ${String(err)}</div>`;
  console.error(err);
});
