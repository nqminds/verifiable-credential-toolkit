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
 * Sign with a PKCS#8 PEM private key of any supported algorithm (Ed25519, ECDSA
 * P-256, ECDSA P-384). The proof's `cryptosuite` is chosen from the key's algorithm
 * (`eddsa-jcs-2022` or `ecdsa-jcs-2019`).
 */
export function sign_with_pem(
  unsigned_vc: UnsignedVerifiableCredential,
  private_key_pem: string
): VerifiableCredential;

/**
 * Verify against a SubjectPublicKeyInfo PEM public key (the `publicKeyPem` form from
 * DID documents) of any supported algorithm. Returns false on any failure.
 */
export function verify_with_pem(
  signed_vc: VerifiableCredential,
  public_key_pem: string
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
