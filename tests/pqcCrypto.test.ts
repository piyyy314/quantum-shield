import { describe, it, expect } from 'vitest';
import {
  generatePqcKeyPair,
  verifyKemRoundTrip,
  verifySignatureRoundTrip,
} from '../src/engine/pqcCrypto.ts';

describe('Real Post-Quantum Cryptography Engine (@noble/post-quantum)', () => {
  it('generates valid NIST FIPS 203 ML-KEM-768 keypairs and verifies shared secret encapsulation', async () => {
    const kp = await generatePqcKeyPair('ml-kem-768');
    expect(kp.publicKeyBytes).toBe(1184);
    expect(kp.secretKeyBytes).toBe(2400);
    expect(kp.fingerprint).toMatch(/^SHA256:[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{8}$/);
    expect(kp.publicKeyPem).toContain('BEGIN ML KEM 768 PUBLIC KEY');

    const kem = await verifyKemRoundTrip('ml-kem-768', kp.publicKey, kp.secretKey);
    expect(kem.verified).toBe(true);
    expect(kem.cipherTextBytes).toBe(1088);
    expect(kem.sharedSecretBytes).toBe(32);
  });

  it('generates and verifies X25519 + ML-KEM-768 hybrid KEM keypairs', async () => {
    const kp = await generatePqcKeyPair('ml-kem-768-x25519');
    expect(kp.kind).toBe('KEM');
    const kem = await verifyKemRoundTrip('ml-kem-768-x25519', kp.publicKey, kp.secretKey);
    expect(kem.verified).toBe(true);
    expect(kem.sharedSecretBytes).toBe(32);
  });

  it('generates valid NIST FIPS 204 ML-DSA-65 keypairs and verifies signatures', async () => {
    const kp = await generatePqcKeyPair('ml-dsa-65');
    expect(kp.publicKeyBytes).toBe(1952);
    expect(kp.secretKeyBytes).toBe(4032);

    const res = verifySignatureRoundTrip(
      'ml-dsa-65',
      'OMB M-23-02 Cryptographic Attestation',
      kp.publicKey,
      kp.secretKey
    );
    expect(res.verified).toBe(true);
    expect(res.signatureBytes).toBe(3309);
  });

  it('generates valid NIST FIPS 205 SLH-DSA-SHA2-128f keypairs and verifies signatures', async () => {
    const kp = await generatePqcKeyPair('slh-dsa-sha2-128f');
    expect(kp.publicKeyBytes).toBe(32);
    expect(kp.secretKeyBytes).toBe(64);

    const res = verifySignatureRoundTrip(
      'slh-dsa-sha2-128f',
      'Stateless Hash Signature Test',
      kp.publicKey,
      kp.secretKey
    );
    expect(res.verified).toBe(true);
    expect(res.signatureBytes).toBe(17088);
  });

  it('rejects mismatched KEM secret keys during decapsulation', async () => {
    const kpA = await generatePqcKeyPair('ml-kem-512');
    const kpB = await generatePqcKeyPair('ml-kem-512');
    const kem = await verifyKemRoundTrip('ml-kem-512', kpA.publicKey, kpB.secretKey);
    expect(kem.verified).toBe(false);
  });
});
