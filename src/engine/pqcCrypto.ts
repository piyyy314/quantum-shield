import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128f, slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

export type PqcAlgorithmId =
  | 'ml-kem-512'
  | 'ml-kem-768'
  | 'ml-kem-1024'
  | 'ml-kem-768-x25519'
  | 'ml-dsa-44'
  | 'ml-dsa-65'
  | 'ml-dsa-87'
  | 'slh-dsa-sha2-128f'
  | 'slh-dsa-sha2-256f';

export interface PqcAlgorithmMetadata {
  id: PqcAlgorithmId;
  displayName: string;
  kind: 'KEM' | 'SIGNATURE';
  nistLevel: 1 | 2 | 3 | 5;
  fipsStandard: string;
  mathBasis: string;
  estimatedLifetime: string;
}

export const PQC_ALGORITHM_CATALOG: Record<PqcAlgorithmId, PqcAlgorithmMetadata> = {
  'ml-kem-512': {
    id: 'ml-kem-512',
    displayName: 'ML-KEM-512',
    kind: 'KEM',
    nistLevel: 1,
    fipsStandard: 'NIST FIPS 203',
    mathBasis: 'Module-LWE Lattice',
    estimatedLifetime: '2035+ (NIST Level 1)',
  },
  'ml-kem-768': {
    id: 'ml-kem-768',
    displayName: 'ML-KEM-768',
    kind: 'KEM',
    nistLevel: 3,
    fipsStandard: 'NIST FIPS 203',
    mathBasis: 'Module-LWE Lattice',
    estimatedLifetime: '2035+ (NIST Level 3)',
  },
  'ml-kem-1024': {
    id: 'ml-kem-1024',
    displayName: 'ML-KEM-1024',
    kind: 'KEM',
    nistLevel: 5,
    fipsStandard: 'NIST FIPS 203 / CNSA 2.0',
    mathBasis: 'Module-LWE Lattice',
    estimatedLifetime: '2040+ (CNSA 2.0 Level 5)',
  },
  'ml-kem-768-x25519': {
    id: 'ml-kem-768-x25519',
    displayName: 'X25519 + ML-KEM-768 (Hybrid)',
    kind: 'KEM',
    nistLevel: 3,
    fipsStandard: 'FIPS 203 + RFC 7748',
    mathBasis: 'Hybrid X25519 ECDH + Module-LWE',
    estimatedLifetime: '2035+ (Defense-in-Depth)',
  },
  'ml-dsa-44': {
    id: 'ml-dsa-44',
    displayName: 'ML-DSA-44',
    kind: 'SIGNATURE',
    nistLevel: 2,
    fipsStandard: 'NIST FIPS 204',
    mathBasis: 'Module-LWE / M-SIS',
    estimatedLifetime: '2035+ (NIST Level 2)',
  },
  'ml-dsa-65': {
    id: 'ml-dsa-65',
    displayName: 'ML-DSA-65',
    kind: 'SIGNATURE',
    nistLevel: 3,
    fipsStandard: 'NIST FIPS 204',
    mathBasis: 'Module-LWE / M-SIS',
    estimatedLifetime: '2035+ (NIST Level 3)',
  },
  'ml-dsa-87': {
    id: 'ml-dsa-87',
    displayName: 'ML-DSA-87',
    kind: 'SIGNATURE',
    nistLevel: 5,
    fipsStandard: 'NIST FIPS 204 / CNSA 2.0',
    mathBasis: 'Module-LWE / M-SIS',
    estimatedLifetime: '2040+ (CNSA 2.0 Level 5)',
  },
  'slh-dsa-sha2-128f': {
    id: 'slh-dsa-sha2-128f',
    displayName: 'SLH-DSA-SHA2-128f',
    kind: 'SIGNATURE',
    nistLevel: 1,
    fipsStandard: 'NIST FIPS 205',
    mathBasis: 'Stateless Hash-Based (SHA-2)',
    estimatedLifetime: '2035+ (Hash Assumption)',
  },
  'slh-dsa-sha2-256f': {
    id: 'slh-dsa-sha2-256f',
    displayName: 'SLH-DSA-SHA2-256f',
    kind: 'SIGNATURE',
    nistLevel: 5,
    fipsStandard: 'NIST FIPS 205',
    mathBasis: 'Stateless Hash-Based (SHA-2)',
    estimatedLifetime: '2040+ (Hash Level 5)',
  },
};

export interface GeneratedPqcKeyPair {
  algorithmId: PqcAlgorithmId;
  algorithm: string;
  kind: 'KEM' | 'SIGNATURE';
  nistLevel: number;
  fipsStandard: string;
  mathBasis: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
  publicKeyBytes: number;
  secretKeyBytes: number;
  estimatedLifetime: string;
  generatedAt: string;
}

export interface KemRoundTripResult {
  cipherTextBytes: number;
  sharedSecretBytes: number;
  sharedSecretSha256: string;
  verified: boolean;
}

export interface SignatureRoundTripResult {
  message: string;
  signatureBytes: number;
  signatureHexPreview: string;
  verified: boolean;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function formatPemBlock(label: string, bytes: Uint8Array): string {
  const b64 = bytesToBase64(bytes);
  const wrapped = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

async function computeSha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer);
  return bytesToHex(new Uint8Array(digest));
}

export async function generatePqcKeyPair(algorithmId: PqcAlgorithmId): Promise<GeneratedPqcKeyPair> {
  const meta = PQC_ALGORITHM_CATALOG[algorithmId];
  let keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };

  switch (algorithmId) {
    case 'ml-kem-512':
      keyPair = ml_kem512.keygen();
      break;
    case 'ml-kem-768':
      keyPair = ml_kem768.keygen();
      break;
    case 'ml-kem-1024':
      keyPair = ml_kem1024.keygen();
      break;
    case 'ml-kem-768-x25519':
      keyPair = ml_kem768_x25519.keygen();
      break;
    case 'ml-dsa-44':
      keyPair = ml_dsa44.keygen();
      break;
    case 'ml-dsa-65':
      keyPair = ml_dsa65.keygen();
      break;
    case 'ml-dsa-87':
      keyPair = ml_dsa87.keygen();
      break;
    case 'slh-dsa-sha2-128f':
      keyPair = slh_dsa_sha2_128f.keygen();
      break;
    case 'slh-dsa-sha2-256f':
      keyPair = slh_dsa_sha2_256f.keygen();
      break;
  }

  const sha256Hex = await computeSha256Hex(keyPair.publicKey);
  const fingerprint = `SHA256:${sha256Hex.slice(0, 8)}:${sha256Hex.slice(8, 16)}:${sha256Hex.slice(16, 24)}:${sha256Hex.slice(24, 32)}`;
  const headerTag = meta.displayName.toUpperCase().replace(/[^A-Z0-9]+/g, ' ').trim();

  return {
    algorithmId,
    algorithm: meta.displayName,
    kind: meta.kind,
    nistLevel: meta.nistLevel,
    fipsStandard: meta.fipsStandard,
    mathBasis: meta.mathBasis,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    publicKeyPem: formatPemBlock(`${headerTag} PUBLIC KEY`, keyPair.publicKey),
    privateKeyPem: formatPemBlock(`${headerTag} PRIVATE KEY`, keyPair.secretKey),
    fingerprint,
    publicKeyBytes: keyPair.publicKey.length,
    secretKeyBytes: keyPair.secretKey.length,
    estimatedLifetime: meta.estimatedLifetime,
    generatedAt: new Date().toISOString(),
  };
}

export async function verifyKemRoundTrip(
  algorithmId: PqcAlgorithmId,
  publicKey: Uint8Array,
  secretKey: Uint8Array
): Promise<KemRoundTripResult> {
  let kem: {
    encapsulate: (pk: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
    decapsulate: (ct: Uint8Array, sk: Uint8Array) => Uint8Array;
  };

  switch (algorithmId) {
    case 'ml-kem-512':
      kem = ml_kem512;
      break;
    case 'ml-kem-768':
      kem = ml_kem768;
      break;
    case 'ml-kem-1024':
      kem = ml_kem1024;
      break;
    case 'ml-kem-768-x25519':
      kem = ml_kem768_x25519;
      break;
    default:
      throw new Error(`Algorithm ${algorithmId} is not a Key Encapsulation Mechanism.`);
  }

  const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
  const recoveredSecret = kem.decapsulate(cipherText, secretKey);

  let verified = sharedSecret.length === recoveredSecret.length;
  for (let i = 0; i < sharedSecret.length && verified; i++) {
    if (sharedSecret[i] !== recoveredSecret[i]) {
      verified = false;
    }
  }

  const sharedSecretSha256 = await computeSha256Hex(sharedSecret);

  return {
    cipherTextBytes: cipherText.length,
    sharedSecretBytes: sharedSecret.length,
    sharedSecretSha256,
    verified,
  };
}

export function verifySignatureRoundTrip(
  algorithmId: PqcAlgorithmId,
  message: string,
  publicKey: Uint8Array,
  secretKey: Uint8Array
): SignatureRoundTripResult {
  const msgBytes = new TextEncoder().encode(message);

  let dsa: {
    sign: (msg: Uint8Array, sk: Uint8Array) => Uint8Array;
    verify: (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array) => boolean;
  };

  switch (algorithmId) {
    case 'ml-dsa-44':
      dsa = ml_dsa44;
      break;
    case 'ml-dsa-65':
      dsa = ml_dsa65;
      break;
    case 'ml-dsa-87':
      dsa = ml_dsa87;
      break;
    case 'slh-dsa-sha2-128f':
      dsa = slh_dsa_sha2_128f;
      break;
    case 'slh-dsa-sha2-256f':
      dsa = slh_dsa_sha2_256f;
      break;
    default:
      throw new Error(`Algorithm ${algorithmId} is not a digital signature scheme.`);
  }

  const signature = dsa.sign(msgBytes, secretKey);
  const verified = dsa.verify(signature, msgBytes, publicKey);

  return {
    message,
    signatureBytes: signature.length,
    signatureHexPreview: `${bytesToHex(signature.subarray(0, 24))}...`,
    verified,
  };
}
