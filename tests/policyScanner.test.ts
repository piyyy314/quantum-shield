import { describe, it, expect } from 'vitest';
import { scanPolicyContent } from '../src/engine/policyScanner.ts';

describe('Static Cryptographic Policy & CWE Scanner', () => {
  it('detects MD5, SHA-1, AES-128, RSA-2048, Math.random, and disabled PQC flags', () => {
    const sample = [
      'HASH_ALG = "MD5"',
      'LEGACY_DIGEST = "sha1"',
      'BLOCK_CIPHER = "AES-128-CBC"',
      'SIGNING_KEY = "rsa2048_key.pem"',
      'const token = Math.random();',
      'PQC_HYBRID_ENABLED = false',
    ].join('\n');

    const findings = scanPolicyContent(sample, 'test.conf');
    const ruleIds = findings.map((f) => f.ruleId);

    expect(ruleIds).toContain('PQC-HASH-001');
    expect(ruleIds).toContain('PQC-HASH-002');
    expect(ruleIds).toContain('PQC-CIPHER-003');
    expect(ruleIds).toContain('PQC-ASYM-002');
    expect(ruleIds).toContain('PQC-RNG-001');
    expect(ruleIds).toContain('PQC-CFG-001');
    expect(findings.every((f) => f.file === 'test.conf')).toBe(true);
  });

  it('ignores pure comment lines to avoid false positives', () => {
    const cleanConfig = [
      '# Migrated away from MD5 and RSA-2048 to ML-DSA-65',
      '// Deprecated SHA-1 removed in v1.0.0',
      'CIPHER_SUITE = "TLS_AES_256_GCM_SHA384"',
      'PQC_HYBRID_ENABLED = true',
    ].join('\n');

    const findings = scanPolicyContent(cleanConfig);
    expect(findings).toHaveLength(0);
  });
});
