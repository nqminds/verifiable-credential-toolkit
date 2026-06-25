export interface UnsignedVerifiableCredential {
  "@context": string[];
  id?: string;
  type: string | string[];
  name?: string | LanguageValue;
  description?: string | LanguageValue;
  issuer: string | IssuerObject;
  credentialSubject: any;
  validFrom?: string;
  validUntil?: string;
  credentialStatus?: Status;
  credentialSchema?: CredentialSchema | CredentialSchema[];
}

export interface VerifiableCredential extends UnsignedVerifiableCredential {
  proof: Proof;
}

export interface LanguageValue {
  "@value": string;
  "@language"?: string;
  "@direction"?: string;
}

export interface IssuerObject {
  id: string;
  [key: string]: any;
}

export interface Status {
  id?: string;
  type: string | string[];
}

export interface CredentialSchema {
  id: string;
  type: string;
}

export interface Proof {
  id?: string;
  type: string;
  proofPurpose: string;
  verificationMethod?: string;
  cryptosuite?: string;
  created?: string;
  expires?: string;
  domain?: string | string[];
  challenge?: string;
  proofValue: string;
  previousProof?: string;
  nonce?: string | string[];
}

/**
 * A 32-byte Ed25519 private (signing) key.
 *
 * Branded so it cannot be mixed up with a `VerifyingKey` at compile time —
 * mirroring the Rust `SigningKey` / `VerifyingKey` newtypes. `KeyPair.signing_key()`
 * returns one; to brand raw bytes loaded from elsewhere, assert the type:
 * `const sk = rawBytes as SigningKey;`
 */
export type SigningKey = Uint8Array & { readonly __brand: "SigningKey" };

/**
 * A 32-byte Ed25519 public (verifying) key. See {@link SigningKey} for the
 * branding rationale; brand raw bytes with `rawBytes as VerifyingKey`.
 */
export type VerifyingKey = Uint8Array & { readonly __brand: "VerifyingKey" };

export class KeyPair {
  constructor(signing_key: Uint8Array, verifying_key: Uint8Array);
  signing_key(): SigningKey;
  verifying_key(): VerifyingKey;
}

export function generate_keypair(): KeyPair;
export function sign(
  unsigned_vc: UnsignedVerifiableCredential,
  private_key: SigningKey
): VerifiableCredential;
export function verify(
  signed_vc: VerifiableCredential,
  public_key: VerifyingKey
): boolean;
export function verify_with_schema_check(
  signed_vc: VerifiableCredential,
  public_key: VerifyingKey,
  schema: any
): boolean;

/**
 * A signature algorithm label accepted by the multi-algorithm functions.
 * Case- and separator-insensitive (e.g. "ML-DSA-65", "mldsa65" both work).
 */
export type AlgorithmLabel =
  | "Ed25519"
  | "ML-DSA-44"
  | "ML-DSA-65"
  | "ML-DSA-87";

/** Generate a key pair for the given algorithm, returning raw key bytes. */
export function generate_keypair_for(algorithm: AlgorithmLabel): KeyPair;

/**
 * Sign with the given algorithm and a raw private key of the matching length
 * (Ed25519: 32 bytes; ML-DSA: the FIPS 204 expanded signing key — 2560 / 4032 / 4896
 * bytes for ML-DSA-44 / 65 / 87).
 */
export function sign_with_algorithm(
  unsigned_vc: UnsignedVerifiableCredential,
  algorithm: AlgorithmLabel,
  private_key: Uint8Array
): VerifiableCredential;

/** Verify with an explicit algorithm and a raw public key. False on any failure. */
export function verify_with_algorithm(
  signed_vc: VerifiableCredential,
  algorithm: AlgorithmLabel,
  public_key: Uint8Array
): boolean;

/**
 * Verify by reading the algorithm from the proof's `cryptosuite` and dispatching
 * automatically — the caller supplies only the raw public key bytes. False on any
 * failure (including an unsupported cryptosuite).
 */
export function verify_auto(
  signed_vc: VerifiableCredential,
  public_key: Uint8Array
): boolean;

// CBOR bindings: encode/decode credentials to and from CBOR bytes, and sign/verify
// CBOR-encoded credential bytes.
export function encode_unsigned_vc_to_cbor(
  unsigned_vc: UnsignedVerifiableCredential
): Uint8Array;
export function encode_signed_vc_to_cbor(
  signed_vc: VerifiableCredential
): Uint8Array;
export function decode_unsigned_vc_from_cbor(
  unsigned_vc_cbor: Uint8Array
): UnsignedVerifiableCredential;
export function decode_signed_vc_from_cbor(
  signed_vc_cbor: Uint8Array
): VerifiableCredential;
export function sign_cbor_vc(
  unsigned_vc_cbor: Uint8Array,
  private_key: SigningKey
): Uint8Array;
export function verify_cbor_vc(
  signed_vc_cbor: Uint8Array,
  public_key: VerifyingKey
): boolean;

// Protobuf bindings: encode/decode credentials to and from Protobuf bytes, and
// sign/verify Protobuf-encoded credential bytes.
export function encode_unsigned_vc_to_protobuf(
  unsigned_vc: UnsignedVerifiableCredential
): Uint8Array;
export function encode_signed_vc_to_protobuf(
  signed_vc: VerifiableCredential
): Uint8Array;
export function decode_unsigned_vc_from_protobuf(
  unsigned_vc_protobuf: Uint8Array
): UnsignedVerifiableCredential;
export function decode_signed_vc_from_protobuf(
  signed_vc_protobuf: Uint8Array
): VerifiableCredential;
export function sign_protobuf_vc(
  unsigned_vc_protobuf: Uint8Array,
  private_key: SigningKey
): Uint8Array;
export function verify_protobuf_vc(
  signed_vc_protobuf: Uint8Array,
  public_key: VerifyingKey
): boolean;

export function normalize_object(input: any): any;
export function normalize_and_stringify(input: any): string;
