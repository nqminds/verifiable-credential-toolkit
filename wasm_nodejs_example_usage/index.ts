// Node.js example — exercises the full WASM API surface and self-checks the
// results, so it doubles as a smoke test (exits non-zero if anything fails).
//
// Run (from this directory):
//   npm run build   # builds WASM, generates pkg/, marks it as CommonJS
//   npm start        # or: node index.ts  (Node >= 22 strips the types)
//
// `npm run build` is needed because wasm-bindgen's `nodejs` target emits
// CommonJS, while this directory is an ES module ("type": "module"); the build
// script writes pkg/package.json with "type": "commonjs" so the import works.

import { readFileSync } from "node:fs";
import {
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
// Data-model types come from the hand-maintained root declaration file; these
// imports are erased at runtime (Node strips them).
import type {
  UnsignedVerifiableCredential,
  VerifiableCredential,
} from "../verifiable_credential_toolkit";

let failures = 0;
function check(label: string, ok: boolean): void {
  console.log(`  ${ok ? "✓" : "✗"} ${label}`);
  if (!ok) failures += 1;
}
function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}
function fixture(relativePath: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(relativePath, import.meta.url)));
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

// ── 1. Key generation ────────────────────────────────────────────────────
section("1. Key generation");
const keypair = generate_keypair();
const signingKey = keypair.signing_key();
const verifyingKey = keypair.verifying_key();
check("signing key is 32 bytes", signingKey.length === 32);
check("verifying key is 32 bytes", verifyingKey.length === 32);

// ── 2. Sign and verify a JSON credential ──────────────────────────────────
section("2. Sign and verify (JSON object)");
const signed: VerifiableCredential = sign(baseVC, signingKey);
check("proof attached", typeof signed.proof?.proofValue === "string");
check(
  "verify succeeds with the right key",
  verify(signed, verifyingKey) === true,
);

// ── 3. Tamper detection ───────────────────────────────────────────────────
section("3. Tamper detection");
const tampered: VerifiableCredential = JSON.parse(JSON.stringify(signed));
tampered.credentialSubject.name = "TAMPERED NAME";
check(
  "tampered credential is rejected",
  verify(tampered, verifyingKey) === false,
);

// ── 4. Wrong key ──────────────────────────────────────────────────────────
section("4. Wrong verifying key");
const other = generate_keypair();
check(
  "a different public key is rejected",
  verify(signed, other.verifying_key()) === false,
);

// ── 5. JSON Schema validation ─────────────────────────────────────────────
section("5. JSON Schema validation");
const schema = {
  type: "object",
  properties: { id: { type: "string" }, name: { type: "string" } },
  required: ["id", "name"],
};
check(
  "verify_with_schema_check passes a matching subject",
  verify_with_schema_check(signed, verifyingKey, schema) === true,
);
const strictSchema = {
  type: "object",
  required: ["id", "name", "serialNumber"], // serialNumber is absent
};
check(
  "verify_with_schema_check fails a missing required field",
  verify_with_schema_check(signed, verifyingKey, strictSchema) === false,
);

// ── 6. Validity period (validFrom / validUntil) ───────────────────────────
section("6. Validity period");
const expired = sign(
  { ...baseVC, validUntil: "2000-01-01T00:00:00Z" },
  signingKey,
);
check(
  "an expired credential is rejected",
  verify(expired, verifyingKey) === false,
);
const notYetValid = sign(
  { ...baseVC, validFrom: "2999-01-01T00:00:00Z" },
  signingKey,
);
check(
  "a not-yet-valid credential is rejected",
  verify(notYetValid, verifyingKey) === false,
);

// ── 7. normalize_object / normalize_and_stringify ─────────────────────────
section("7. normalize helpers");
const messy = { a: 1, b: undefined, c: null, d: { e: undefined, f: 2 } };
const normalized = normalize_object(messy) as Record<string, unknown>;
check("undefined keys are stripped", !("b" in normalized) && "a" in normalized);
const normalizedString = normalize_and_stringify(messy);
check(
  "normalize_and_stringify returns JSON text",
  typeof normalizedString === "string" && normalizedString.includes('"a":1'),
);

// ── 8. CBOR bindings ──────────────────────────────────────────────────────
// The unsigned credential is loaded from a fixture encoded by the Rust side
// (google.protobuf.Value / canonical CBOR are impractical to hand-encode in JS).
section("8. CBOR bindings");
const unsignedCbor = fixture("./fixtures/unsigned_vc.cbor");
const signedCbor = sign_cbor_vc(unsignedCbor, signingKey);
check(
  "sign_cbor_vc returns bytes",
  signedCbor instanceof Uint8Array && signedCbor.length > 0,
);
check(
  "verify_cbor_vc succeeds",
  verify_cbor_vc(signedCbor, verifyingKey) === true,
);
let cborRejected = false;
try {
  verify_cbor_vc(flipMiddleByte(signedCbor), verifyingKey);
} catch {
  cborRejected = true;
}
check("tampered CBOR is rejected", cborRejected);

// ── 9. Protobuf bindings ──────────────────────────────────────────────────
section("9. Protobuf bindings");
const unsignedPb = fixture("./fixtures/unsigned_vc.pb");
const signedPb = sign_protobuf_vc(unsignedPb, signingKey);
check(
  "sign_protobuf_vc returns bytes",
  signedPb instanceof Uint8Array && signedPb.length > 0,
);
check(
  "verify_protobuf_vc succeeds",
  verify_protobuf_vc(signedPb, verifyingKey) === true,
);
let pbRejected = false;
try {
  verify_protobuf_vc(flipMiddleByte(signedPb), verifyingKey);
} catch {
  pbRejected = true;
}
check("tampered Protobuf is rejected", pbRejected);

// ── Summary ───────────────────────────────────────────────────────────────
section("Summary");
if (failures === 0) {
  console.log("  All checks passed ✓");
} else {
  console.log(`  ${failures} check(s) failed ✗`);
  process.exit(1);
}
