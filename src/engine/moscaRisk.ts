import type { PrimitiveCategory, RiskLevel } from '../types/quantum.ts';

export interface MoscaEvaluation {
  shelfLifeX: number;
  migrationTimeY: number;
  crqcHorizonZ: number;
  totalExposureYears: number;
  isBreached: boolean;
  breachDeficitYears: number;
}

/**
 * Evaluates Dr. Michele Mosca's theorem:
 * If X (shelf-life) + Y (migration time) > Z (time until CRQC),
 * ciphertext intercepted today faces Store Now, Decrypt Later compromise.
 */
export function calculateMoscaExposure(
  shelfLifeX: number,
  migrationTimeY: number,
  crqcHorizonZ: number
): MoscaEvaluation {
  const totalExposureYears = shelfLifeX + migrationTimeY;
  const breachDeficitYears = totalExposureYears - crqcHorizonZ;
  return {
    shelfLifeX,
    migrationTimeY,
    crqcHorizonZ,
    totalExposureYears,
    isBreached: totalExposureYears > crqcHorizonZ,
    breachDeficitYears,
  };
}

export function classifyPrimitiveRisk(
  algorithm: string,
  keySize: number,
  primitiveType: PrimitiveCategory
): { risk: RiskLevel; recommendedPQC: string } {
  const normalized = algorithm.toUpperCase();

  if (
    primitiveType === 'PQC Native' ||
    normalized.includes('ML-KEM') ||
    normalized.includes('ML-DSA') ||
    normalized.includes('SLH-DSA') ||
    normalized.includes('KYBER') ||
    normalized.includes('DILITHIUM')
  ) {
    return {
      risk: 'COMPLIANT',
      recommendedPQC: 'NIST FIPS 203/204/205 Compliant',
    };
  }

  if (primitiveType === 'PQC Hybrid') {
    return {
      risk: 'LOW',
      recommendedPQC: 'Migrate to pure ML-KEM-1024 / ML-DSA-87 by 2030',
    };
  }

  if (normalized.includes('MD5') || normalized.includes('SHA-1') || normalized.includes('SHA1') || normalized.includes('RC4') || normalized.includes('DES')) {
    return {
      risk: 'CRITICAL',
      recommendedPQC: 'SHA-384 / AES-256-GCM (Immediate Removal)',
    };
  }

  if (primitiveType === 'Asymmetric' || normalized.includes('RSA') || normalized.includes('ECDSA') || normalized.includes('ECDH') || normalized.includes('ED25519') || normalized.includes('X25519') || normalized.includes('DH')) {
    if (normalized.includes('RSA') && keySize < 2048) {
      return {
        risk: 'CRITICAL',
        recommendedPQC: 'ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)',
      };
    }
    return {
      risk: normalized.includes('RSA') || normalized.includes('ECDH') || normalized.includes('ECDSA') ? 'CRITICAL' : 'HIGH',
      recommendedPQC: normalized.includes('SIGN') || normalized.includes('DSA')
        ? 'ML-DSA-65 / ML-DSA-87 (FIPS 204)'
        : 'X25519+ML-KEM-768 Hybrid / ML-KEM-1024',
    };
  }

  if (primitiveType === 'Symmetric') {
    if (keySize < 256) {
      return {
        risk: 'MEDIUM',
        recommendedPQC: 'AES-256-GCM (CNSA 2.0)',
      };
    }
    return {
      risk: 'COMPLIANT',
      recommendedPQC: 'AES-256-GCM / ChaCha20-Poly1305 (Grover-Resilient)',
    };
  }

  if (primitiveType === 'Hash') {
    if (keySize < 256) {
      return {
        risk: 'HIGH',
        recommendedPQC: 'SHA-384 / SHA-512 (CNSA 2.0)',
      };
    }
    return {
      risk: keySize >= 384 ? 'COMPLIANT' : 'LOW',
      recommendedPQC: keySize >= 384 ? 'SHA-384 / SHA-512 Compliant' : 'Upgrade to SHA-384 for CNSA 2.0',
    };
  }

  return {
    risk: 'MEDIUM',
    recommendedPQC: 'Evaluate against NIST IR 8547',
  };
}

export interface TlsPostureEvaluation {
  quantumSafeGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
  quantumSafetyScore: number;
  isHybridPQC: boolean;
  recommendations: string[];
}

export function evaluateTlsPosture(params: {
  tlsVersion: string;
  keyExchange: string;
  signatureAlgorithm: string;
  publicKeyType?: string;
  publicKeyBits?: number | null;
}): TlsPostureEvaluation {
  const { tlsVersion, keyExchange, signatureAlgorithm, publicKeyType, publicKeyBits } = params;
  let score = 0;
  const recommendations: string[] = [];

  const kexUpper = keyExchange.toUpperCase();
  const sigUpper = signatureAlgorithm.toUpperCase();
  const isPqcKex =
    kexUpper.includes('MLKEM') ||
    kexUpper.includes('ML-KEM') ||
    kexUpper.includes('KYBER');
  const isPqcSig =
    sigUpper.includes('ML-DSA') ||
    sigUpper.includes('MLDSA') ||
    sigUpper.includes('SLH-DSA') ||
    sigUpper.includes('DILITHIUM');

  // Protocol score (max 25)
  if (tlsVersion === 'TLSv1.3') {
    score += 25;
  } else if (tlsVersion === 'TLSv1.2') {
    score += 10;
    recommendations.push('Upgrade endpoint minimum protocol from TLS 1.2 to TLS 1.3 (RFC 8446).');
  } else {
    recommendations.push(`Prohibited legacy protocol (${tlsVersion}) detected. Disable immediately and enforce TLS 1.3.`);
  }

  // Key exchange score (max 45)
  if (isPqcKex) {
    score += 45;
  } else if (
    kexUpper.includes('X25519') ||
    kexUpper.includes('ECDHE') ||
    kexUpper.includes('ECDH') ||
    kexUpper.includes('P-256') ||
    kexUpper.includes('P-384') ||
    kexUpper.includes('PRIME256') ||
    kexUpper.includes('SECP')
  ) {
    score += 18;
    recommendations.push(
      `Classical ephemeral key exchange (${keyExchange}) is vulnerable to Store Now, Decrypt Later (SNDL). Enable X25519MLKEM768 hybrid key agreement.`
    );
  } else {
    recommendations.push(
      `Static or legacy key exchange (${keyExchange}) lacks post-quantum forward secrecy. Deploy ML-KEM hybrid TLS 1.3.`
    );
  }

  // Certificate & signature scheme score (max 30)
  if (isPqcSig) {
    score += 30;
  } else if (sigUpper.includes('ECDSA') || sigUpper.includes('ED25519') || sigUpper.includes('ED448')) {
    score += 15;
    recommendations.push(
      `Leaf certificate uses classical asymmetric signature (${publicKeyType || signatureAlgorithm}). Plan CA chain transition to ML-DSA-65/87 (FIPS 204).`
    );
  } else if (sigUpper.includes('RSA')) {
    if (publicKeyBits && publicKeyBits < 2048) {
      score += 0;
      recommendations.push(`Weak RSA-${publicKeyBits} certificate detected. Replace immediately.`);
    } else {
      score += 10;
      recommendations.push(
        `Certificate uses RSA-${publicKeyBits ?? 2048}, which is vulnerable to Shor factoring. Prepare migration to ML-DSA (FIPS 204).`
      );
    }
  } else {
    score += 10;
    recommendations.push('Verify certificate chain signature algorithm supports FIPS 204 migration.');
  }

  let grade: 'A+' | 'A' | 'B' | 'C' | 'F' = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 65) grade = 'B';
  else if (score >= 45) grade = 'C';

  if (recommendations.length === 0) {
    recommendations.push('Endpoint satisfies TLS 1.3 + post-quantum key exchange and signature baselines.');
  }

  return {
    quantumSafeGrade: grade,
    quantumSafetyScore: Math.min(100, Math.max(0, score)),
    isHybridPQC: isPqcKex,
    recommendations,
  };
}
