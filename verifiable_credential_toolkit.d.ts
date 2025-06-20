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

export class KeyPair {
  constructor(signing_key: Uint8Array, verifying_key: Uint8Array);
  signing_key(): Uint8Array;
  verifying_key(): Uint8Array;
}

export function generate_keypair(): KeyPair;
export function sign(
  unsigned_vc: UnsignedVerifiableCredential,
  private_key: Uint8Array
): VerifiableCredential;
export function verify(
  signed_vc: VerifiableCredential,
  public_key: Uint8Array
): boolean;
export function verify_with_schema_check(
  signed_vc: VerifiableCredential,
  public_key: Uint8Array,
  schema: any
): boolean;
export function normalize_object(input: any): any;
export function normalize_and_stringify(input: any): string;
