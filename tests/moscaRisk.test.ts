import { describe, it, expect } from 'vitest';
import {
  calculateMoscaExposure,
  classifyPrimitiveRisk,
  evaluateTlsPosture,
} from '../src/engine/moscaRisk.ts';

describe('Mosca Theorem & Risk Classification Engine', () => {
  it('flags SNDL breach when X + Y > Z', () => {
    const result = calculateMoscaExposure(10, 3, 7);
    expect(result.totalExposureYears).toBe(13);
    expect(result.isBreached).toBe(true);
    expect(result.breachDeficitYears).toBe(6);
  });

  it('reports safe migration buffer when X + Y <= Z', () => {
    const result = calculateMoscaExposure(4, 2, 8);
    expect(result.totalExposureYears).toBe(6);
    expect(result.isBreached).toBe(false);
    expect(result.breachDeficitYears).toBe(-2);
  });

  it('classifies RSA-2048 as CRITICAL and AES-256-GCM as COMPLIANT', () => {
    const rsa = classifyPrimitiveRisk('RSA-2048', 2048, 'Asymmetric');
    expect(rsa.risk).toBe('CRITICAL');

    const aes = classifyPrimitiveRisk('AES-256-GCM', 256, 'Symmetric');
    expect(aes.risk).toBe('COMPLIANT');
  });

  it('grades TLS 1.3 + X25519MLKEM768 + ML-DSA-87 as A+', () => {
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
  });

  it('grades classical TLS 1.2 + RSA-2048 poorly and emits actionable recommendations', () => {
    const posture = evaluateTlsPosture({
      tlsVersion: 'TLSv1.2',
      keyExchange: 'ECDHE-RSA',
      signatureAlgorithm: 'RSA with SHA256',
      publicKeyType: 'RSA',
      publicKeyBits: 2048,
    });
    expect(posture.quantumSafeGrade).toBe('F');
    expect(posture.isHybridPQC).toBe(false);
    expect(posture.recommendations.length).toBeGreaterThanOrEqual(2);
  });
});
