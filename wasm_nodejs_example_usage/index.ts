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

import {
  generate_keypair,
  sign,
  verify,
  verify_with_schema_check,
  normalize_object,
  normalize_and_stringify,
  encode_unsigned_vc_to_cbor,
  encode_signed_vc_to_cbor,
  decode_unsigned_vc_from_cbor,
  decode_signed_vc_from_cbor,
  sign_cbor_vc,
  verify_cbor_vc,
  encode_unsigned_vc_to_protobuf,
  encode_signed_vc_to_protobuf,
  decode_unsigned_vc_from_protobuf,
  decode_signed_vc_from_protobuf,
  sign_protobuf_vc,
  verify_protobuf_vc,
  generate_keypair_for,
  sign_with_algorithm,
  verify_with_algorithm,
  verify_auto,
  sign_cbor_vc_with_algorithm,
  verify_cbor_vc_auto,
  sign_protobuf_vc_with_algorithm,
  verify_protobuf_vc_auto,
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
// Full round-trip, all in JS: encode the credential object to bytes, decode it
// back, sign, verify, and re-encode the decoded credential.
section("8. CBOR bindings");
const unsignedCbor = encode_unsigned_vc_to_cbor(baseVC);
check(
  "encode_unsigned_vc_to_cbor returns bytes",
  unsignedCbor instanceof Uint8Array && unsignedCbor.length > 0,
);
const decodedUnsignedCbor = decode_unsigned_vc_from_cbor(unsignedCbor);
check(
  "decode_unsigned_vc_from_cbor round-trips the credential",
  JSON.stringify(decodedUnsignedCbor.type) === JSON.stringify(baseVC.type),
);
const signedCbor = sign_cbor_vc(unsignedCbor, signingKey);
check(
  "verify_cbor_vc succeeds",
  verify_cbor_vc(signedCbor, verifyingKey) === true,
);
const decodedSignedCbor = decode_signed_vc_from_cbor(signedCbor);
check(
  "decode_signed_vc_from_cbor exposes the proof",
  typeof decodedSignedCbor.proof?.proofValue === "string",
);
check(
  "re-encoding the decoded signed credential still verifies",
  verify_cbor_vc(encode_signed_vc_to_cbor(decodedSignedCbor), verifyingKey) ===
    true,
);
let cborRejected = false;
try {
  verify_cbor_vc(flipMiddleByte(signedCbor), verifyingKey);
} catch {
  cborRejected = true;
}
check("tampered CBOR is rejected", cborRejected);

// ── 9. Protobuf bindings ──────────────────────────────────────────────────
// Identical round-trip via Protobuf, again entirely from the JS credential object.
section("9. Protobuf bindings");
const unsignedPb = encode_unsigned_vc_to_protobuf(baseVC);
check(
  "encode_unsigned_vc_to_protobuf returns bytes",
  unsignedPb instanceof Uint8Array && unsignedPb.length > 0,
);
const decodedUnsignedPb = decode_unsigned_vc_from_protobuf(unsignedPb);
check(
  "decode_unsigned_vc_from_protobuf round-trips the credential",
  JSON.stringify(decodedUnsignedPb.type) === JSON.stringify(baseVC.type),
);
const signedPb = sign_protobuf_vc(unsignedPb, signingKey);
check(
  "verify_protobuf_vc succeeds",
  verify_protobuf_vc(signedPb, verifyingKey) === true,
);
const decodedSignedPb = decode_signed_vc_from_protobuf(signedPb);
check(
  "decode_signed_vc_from_protobuf exposes the proof",
  typeof decodedSignedPb.proof?.proofValue === "string",
);
check(
  "re-encoding the decoded signed credential still verifies",
  verify_protobuf_vc(
    encode_signed_vc_to_protobuf(decodedSignedPb),
    verifyingKey,
  ) === true,
);
let pbRejected = false;
try {
  verify_protobuf_vc(flipMiddleByte(signedPb), verifyingKey);
} catch {
  pbRejected = true;
}
check("tampered Protobuf is rejected", pbRejected);

// ── 10. Post-quantum ML-DSA (multi-algorithm API) ─────────────────────────
// The same JSON / CBOR / Protobuf round-trips, but signed with ML-DSA-65 instead
// of Ed25519. `generate_keypair_for` returns raw FIPS-204 key bytes; `verify_auto`
// reads the algorithm from the proof's cryptosuite, so the verifier only needs the
// public key. Signatures are interoperable across all three formats.
section("10. Post-quantum ML-DSA");
const ALG = "ML-DSA-65";
const pqKeys = generate_keypair_for(ALG);
const pqSk = pqKeys.signing_key();
const pqPk = pqKeys.verifying_key();
check("ML-DSA-65 private key is 4032 bytes", pqSk.length === 4032);
check("ML-DSA-65 public key is 1952 bytes", pqPk.length === 1952);

const pqSigned: VerifiableCredential = sign_with_algorithm(baseVC, ALG, pqSk);
check(
  "ML-DSA cryptosuite is recorded in the proof",
  pqSigned.proof?.cryptosuite === "mldsa65-jcs-2025",
);
check(
  "verify_with_algorithm succeeds",
  verify_with_algorithm(pqSigned, ALG, pqPk) === true,
);
check("verify_auto (reads the cryptosuite) succeeds", verify_auto(pqSigned, pqPk) === true);

const pqTampered: VerifiableCredential = JSON.parse(JSON.stringify(pqSigned));
pqTampered.credentialSubject.name = "TAMPERED NAME";
check("tampered ML-DSA credential is rejected", verify_auto(pqTampered, pqPk) === false);
check("a wrong ML-DSA key is rejected", verify_auto(pqSigned, generate_keypair_for(ALG).verifying_key()) === false);

// ML-DSA over CBOR and Protobuf, signed once via JSON and re-verified after transport.
const pqCbor = sign_cbor_vc_with_algorithm(encode_unsigned_vc_to_cbor(baseVC), ALG, pqSk);
check("ML-DSA over CBOR verifies (verify_cbor_vc_auto)", verify_cbor_vc_auto(pqCbor, pqPk) === true);
const pqPb = sign_protobuf_vc_with_algorithm(encode_unsigned_vc_to_protobuf(baseVC), ALG, pqSk);
check(
  "ML-DSA over Protobuf verifies (verify_protobuf_vc_auto)",
  verify_protobuf_vc_auto(pqPb, pqPk) === true,
);

// ── Summary ───────────────────────────────────────────────────────────────
section("Summary");
if (failures === 0) {
  console.log("  All checks passed ✓");
} else {
  console.log(`  ${failures} check(s) failed ✗`);
  process.exit(1);
}
