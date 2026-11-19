import { describe, it, expect } from 'vitest';
import {
  calculateMoscaExposure,
  classifyPrimitiveRisk,
  evaluateTlsPosture,
} from '../src/engine/moscaRisk.ts';
import { ALGORITHM_PROFILES } from '../src/data/nistStandards.ts';

describe("Core Cryptographic Risk Engine (Mosca's Theorem & NIST Compliance)", () => {
  describe('calculateMoscaExposure (X + Y > Z)', () => {
    it('flags SNDL breach when X + Y > Z', () => {
      const result = calculateMoscaExposure(10, 3, 7);
      expect(result.totalExposureYears).toBe(13);
      expect(result.isBreached).toBe(true);
      expect(result.breachDeficitYears).toBe(6);
    });

    it('treats exact boundary X + Y === Z as non-breached with zero buffer', () => {
      const result = calculateMoscaExposure(5, 2, 7);
      expect(result.totalExposureYears).toBe(7);
      expect(result.isBreached).toBe(false);
      expect(result.breachDeficitYears).toBe(0);
    });

    it('reports safe migration buffer when X + Y < Z', () => {
      const result = calculateMoscaExposure(4, 2, 8);
      expect(result.totalExposureYears).toBe(6);
      expect(result.isBreached).toBe(false);
      expect(result.breachDeficitYears).toBe(-2);
    });
  });

  describe('classifyPrimitiveRisk against NIST FIPS 203/204/205, SP 800-131A, and CNSA 2.0', () => {
    it('validates all NIST FIPS 203/204/205 standardized PQC algorithms as COMPLIANT', () => {
      const pqcAlgorithms = [
        { name: 'ML-KEM-512', bits: 512 },
        { name: 'ML-KEM-768', bits: 768 },
        { name: 'ML-KEM-1024', bits: 1024 },
        { name: 'ML-DSA-44', bits: 1312 },
        { name: 'ML-DSA-65', bits: 1952 },
        { name: 'ML-DSA-87', bits: 2592 },
        { name: 'SLH-DSA-SHA2-128f', bits: 128 },
        { name: 'SLH-DSA-SHA2-256f', bits: 256 },
        { name: 'CRYSTALS-Kyber', bits: 768 },
        { name: 'CRYSTALS-Dilithium', bits: 1952 },
      ];

      for (const algo of pqcAlgorithms) {
        const res = classifyPrimitiveRisk(algo.name, algo.bits, 'PQC Native');
        expect(res.risk).toBe('COMPLIANT');
        expect(res.recommendedPQC).toContain('FIPS 203/204/205');
      }
    });

    it('classifies hybrid PQC deployments as LOW risk with 2030 pure-PQC guidance', () => {
      const hybrid = classifyPrimitiveRisk('X25519+ML-KEM-768', 768, 'PQC Hybrid');
      expect(hybrid.risk).toBe('LOW');
      expect(hybrid.recommendedPQC).toContain('ML-KEM-1024');
    });

    it('flags NIST SP 800-131A disallowed legacy hashes and ciphers as CRITICAL', () => {
      for (const broken of ['MD5', 'SHA-1', 'SHA1', 'RC4', 'DES', '3DES']) {
        const res = classifyPrimitiveRisk(broken, 128, 'Symmetric');
        expect(res.risk).toBe('CRITICAL');
        expect(res.recommendedPQC).toContain('Immediate Removal');
      }
    });

    it('classifies Shor-vulnerable asymmetric algorithms with FIPS 203/204 migration targets', () => {
      const rsa1024 = classifyPrimitiveRisk('RSA-1024', 1024, 'Asymmetric');
      expect(rsa1024.risk).toBe('CRITICAL');

      const rsa2048 = classifyPrimitiveRisk('RSA-2048', 2048, 'Asymmetric');
      expect(rsa2048.risk).toBe('CRITICAL');
      expect(rsa2048.recommendedPQC).toContain('ML-KEM');

      const rsa4096 = classifyPrimitiveRisk('RSA-4096', 4096, 'Asymmetric');
      expect(rsa4096.risk).toBe('CRITICAL');

      const ecdsa = classifyPrimitiveRisk('ECDSA P-256', 256, 'Asymmetric');
      expect(ecdsa.risk).toBe('CRITICAL');
      expect(ecdsa.recommendedPQC).toContain('ML-DSA');

      const ecdh = classifyPrimitiveRisk('ECDH P-384', 384, 'Asymmetric');
      expect(ecdh.risk).toBe('CRITICAL');

      const ed25519 = classifyPrimitiveRisk('Ed25519 Sign', 256, 'Asymmetric');
      expect(ed25519.risk).toBe('HIGH');
      expect(ed25519.recommendedPQC).toContain('ML-DSA');

      const x25519 = classifyPrimitiveRisk('X25519', 256, 'Asymmetric');
      expect(x25519.risk).toBe('HIGH');
      expect(x25519.recommendedPQC).toContain('ML-KEM');
    });

    it('enforces NSA CNSA 2.0 256-bit requirement on symmetric ciphers under Grover search', () => {
      const aes128 = classifyPrimitiveRisk('AES-128-GCM', 128, 'Symmetric');
      expect(aes128.risk).toBe('MEDIUM');
      expect(aes128.recommendedPQC).toContain('AES-256');

      const aes192 = classifyPrimitiveRisk('AES-192-GCM', 192, 'Symmetric');
      expect(aes192.risk).toBe('MEDIUM');

      const aes256 = classifyPrimitiveRisk('AES-256-GCM', 256, 'Symmetric');
      expect(aes256.risk).toBe('COMPLIANT');

      const chacha = classifyPrimitiveRisk('ChaCha20-Poly1305', 256, 'Symmetric');
      expect(chacha.risk).toBe('COMPLIANT');
    });

    it('enforces CNSA 2.0 SHA-384/512 minimums for cryptographic hash functions', () => {
      const sha224 = classifyPrimitiveRisk('SHA-224', 224, 'Hash');
      expect(sha224.risk).toBe('HIGH');

      const sha256 = classifyPrimitiveRisk('SHA-256', 256, 'Hash');
      expect(sha256.risk).toBe('LOW');
      expect(sha256.recommendedPQC).toContain('SHA-384');

      const sha384 = classifyPrimitiveRisk('SHA-384', 384, 'Hash');
      expect(sha384.risk).toBe('COMPLIANT');

      const sha512 = classifyPrimitiveRisk('SHA-512', 512, 'Hash');
      expect(sha512.risk).toBe('COMPLIANT');
    });
  });

  describe('evaluateTlsPosture NIST & CNSA 2.0 grading matrix', () => {
    it('awards Grade A+ (100/100) for TLS 1.3 + ML-KEM hybrid + FIPS 204/205 signature', () => {
      const posture = evaluateTlsPosture({
        tlsVersion: 'TLSv1.3',
        keyExchange: 'X25519MLKEM768',
        signatureAlgorithm: 'ML-DSA-87',
        publicKeyType: 'ML-DSA',
        publicKeyBits: 2592,
      });
      expect(posture.quantumSafeGrade).toBe('A+');
      expect(posture.quantumSafetyScore).toBe(100);
      expect(posture.isHybridPQC).toBe(true);
      expect(posture.recommendations[0]).toContain('satisfies TLS 1.3');
    });

    it('awards Grade A (85/100) for TLS 1.3 + X25519MLKEM768 + classical ECDSA leaf cert', () => {
      const posture = evaluateTlsPosture({
        tlsVersion: 'TLSv1.3',
        keyExchange: 'X25519MLKEM768 (FIPS 203 Hybrid)',
        signatureAlgorithm: 'ECDSA with SHA256',
        publicKeyType: 'EC',
        publicKeyBits: 256,
      });
      expect(posture.quantumSafeGrade).toBe('A');
      expect(posture.quantumSafetyScore).toBe(85);
      expect(posture.isHybridPQC).toBe(true);
      expect(posture.recommendations.some((r) => r.includes('ML-DSA'))).toBe(true);
    });

    it('awards Grade B (70/100) for TLS 1.2 with PQC KEM + ECDSA', () => {
      const posture = evaluateTlsPosture({
        tlsVersion: 'TLSv1.2',
        keyExchange: 'X25519-Kyber768',
        signatureAlgorithm: 'ECDSA',
        publicKeyType: 'EC',
        publicKeyBits: 256,
      });
      expect(posture.quantumSafeGrade).toBe('B');
      expect(posture.quantumSafetyScore).toBe(70);
      expect(posture.isHybridPQC).toBe(true);
    });

    it('awards Grade C (58/100) for modern classical TLS 1.3 (X25519/prime256v1 + ECDSA)', () => {
      for (const kex of ['X25519, 253 bits', 'ECDH, prime256v1, 256 bits', 'ECDHE P-384']) {
        const posture = evaluateTlsPosture({
          tlsVersion: 'TLSv1.3',
          keyExchange: kex,
          signatureAlgorithm: 'ECDSA with SHA256',
          publicKeyType: 'EC',
          publicKeyBits: 256,
        });
        expect(posture.quantumSafeGrade).toBe('C');
        expect(posture.quantumSafetyScore).toBe(58);
        expect(posture.isHybridPQC).toBe(false);
      }
    });

    it('awards Grade F and flags weak RSA-1024 and prohibited TLS 1.0/1.1 protocols', () => {
      const legacyTls12 = evaluateTlsPosture({
        tlsVersion: 'TLSv1.2',
        keyExchange: 'ECDHE-RSA',
        signatureAlgorithm: 'RSA with SHA256',
        publicKeyType: 'RSA',
        publicKeyBits: 2048,
      });
      expect(legacyTls12.quantumSafeGrade).toBe('F');
      expect(legacyTls12.quantumSafetyScore).toBe(38);
      expect(legacyTls12.isHybridPQC).toBe(false);

      const prohibitedTls10 = evaluateTlsPosture({
        tlsVersion: 'TLSv1.0',
        keyExchange: 'RSA-1024 Static',
        signatureAlgorithm: 'RSA with SHA1',
        publicKeyType: 'RSA',
        publicKeyBits: 1024,
      });
      expect(prohibitedTls10.quantumSafeGrade).toBe('F');
      expect(prohibitedTls10.quantumSafetyScore).toBe(0);
      expect(prohibitedTls10.recommendations.some((r) => r.includes('Prohibited legacy protocol'))).toBe(true);
      expect(prohibitedTls10.recommendations.some((r) => r.includes('Weak RSA-1024'))).toBe(true);
    });
  });

  describe('NIST Algorithm Catalog Compliance Validation', () => {
    it('ensures every profile in ALGORITHM_PROFILES aligns with classifyPrimitiveRisk severity', () => {
      expect(ALGORITHM_PROFILES.length).toBeGreaterThanOrEqual(10);

      for (const profile of ALGORITHM_PROFILES) {
        expect(profile.reference).toMatch(/NIST|CNSA|FIPS|IETF/);
        if (profile.quantumThreat === 'Standardized') {
          expect(profile.threatSeverity).toBe('COMPLIANT');
          expect(profile.standardStatus).toMatch(/FIPS 20[345]/);
        }
        if (profile.quantumThreat === 'Shor') {
          expect(['CRITICAL', 'HIGH']).toContain(profile.threatSeverity);
        }
      }
    });
  });
});
