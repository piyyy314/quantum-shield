import type { PolicyFinding, RiskLevel } from '../types/quantum.ts';

interface PolicyRule {
  id: string;
  cwe: string;
  title: string;
  severity: RiskLevel;
  standard: string;
  pattern: RegExp;
  fix: string;
}

const POLICY_RULES: PolicyRule[] = [
  {
    id: 'PQC-HASH-001',
    cwe: 'CWE-328',
    title: 'Prohibited Cryptographic Hash (MD5)',
    severity: 'CRITICAL',
    standard: 'NIST SP 800-131A Rev 2 / FIPS 180-4',
    pattern: /\bmd5\b/i,
    fix: 'Replace MD5 with SHA-384 or SHA-512 (CNSA 2.0) or SHA-3-256/384.',
  },
  {
    id: 'PQC-HASH-002',
    cwe: 'CWE-328',
    title: 'Deprecated Cryptographic Hash (SHA-1)',
    severity: 'CRITICAL',
    standard: 'NIST SP 800-131A Rev 2',
    pattern: /\bsha[-_]?1\b/i,
    fix: 'Replace SHA-1 with SHA-256, SHA-384, or SHA-512 for digital signatures and integrity verification.',
  },
  {
    id: 'PQC-CIPHER-001',
    cwe: 'CWE-327',
    title: 'Broken Symmetric Cipher (DES / 3DES / RC4)',
    severity: 'CRITICAL',
    standard: 'NIST SP 800-131A Rev 2',
    pattern: /\b(3des|triple[-_]?des|des-ede3|des-cbc|rc4|arcfour)\b/i,
    fix: 'Migrate immediately to AES-256-GCM or ChaCha20-Poly1305.',
  },
  {
    id: 'PQC-CIPHER-002',
    cwe: 'CWE-327',
    title: 'Insecure Block Cipher Mode (AES-ECB)',
    severity: 'HIGH',
    standard: 'NIST SP 800-38A / CWE-327',
    pattern: /\baes[-_]?(128|192|256)?[-_]?ecb\b/i,
    fix: 'Replace ECB mode with authenticated encryption (AES-256-GCM).',
  },
  {
    id: 'PQC-CIPHER-003',
    cwe: 'CWE-326',
    title: 'Borderline Grover Key Length (AES-128)',
    severity: 'MEDIUM',
    standard: 'NSA CNSA 2.0',
    pattern: /\baes[-_]?128\b/i,
    fix: 'Upgrade AES-128 to AES-256-GCM to maintain >= 128-bit post-Grover security margin.',
  },
  {
    id: 'PQC-ASYM-001',
    cwe: 'CWE-326',
    title: 'Disallowed Weak RSA Modulus (< 2048-bit)',
    severity: 'CRITICAL',
    standard: 'NIST SP 800-131A Rev 2',
    pattern: /\brsa[-_]?(512|768|1024)(?![0-9])/i,
    fix: 'Decommission sub-2048-bit RSA immediately and migrate to ML-KEM / ML-DSA.',
  },
  {
    id: 'PQC-ASYM-002',
    cwe: 'CWE-327',
    title: 'Shor-Vulnerable RSA-2048 / RSA-4096 Primitive',
    severity: 'HIGH',
    standard: 'NIST IR 8547 / FIPS 203 & 204',
    pattern: /\brsa[-_]?(2048|3072|4096)(?![0-9])|\brsa[_-]private\b/i,
    fix: 'Plan migration to ML-KEM-768/1024 (FIPS 203) for key exchange and ML-DSA-65/87 (FIPS 204) for signatures.',
  },
  {
    id: 'PQC-KEX-001',
    cwe: 'CWE-327',
    title: 'Classical Diffie-Hellman Group Key Exchange',
    severity: 'CRITICAL',
    standard: 'NIST IR 8547 / FIPS 203',
    pattern: /\bdiffie[-_]?hellman[-_]?group(1|2|5|14)\b|\bdh[-_]?group(1|2|5|14)\b/i,
    fix: 'Replace classical DH groups with X25519+ML-KEM-768 hybrid or ML-KEM-1024.',
  },
  {
    id: 'PQC-TLS-001',
    cwe: 'CWE-327',
    title: 'Prohibited Legacy Transport Protocol (SSLv3 / TLS 1.0 / TLS 1.1)',
    severity: 'CRITICAL',
    standard: 'NIST SP 800-52 Rev 2 / RFC 8996',
    pattern: /\b(sslv2|sslv3|tlsv?[-_]?1[._]0|tlsv?[-_]?1[._]1)\b/i,
    fix: 'Enforce TLS 1.3 (RFC 8446) with post-quantum hybrid key exchange.',
  },
  {
    id: 'PQC-RNG-001',
    cwe: 'CWE-338',
    title: 'Non-Cryptographic PRNG (Math.random)',
    severity: 'HIGH',
    standard: 'NIST SP 800-90A / CWE-338',
    pattern: /\bMath\.random\s*\(/,
    fix: 'Use Web Crypto crypto.getRandomValues() or Node.js crypto.randomBytes() / randomUUID().',
  },
  {
    id: 'PQC-CFG-001',
    cwe: 'CWE-327',
    title: 'Post-Quantum Hybrid Negotiation Explicitly Disabled',
    severity: 'HIGH',
    standard: 'NSA CNSA 2.0 / OMB M-23-02',
    pattern: /\b(pqc_hybrid_enabled|enable_pqc|ml_kem_enabled)\s*[:=]\s*false\b/i,
    fix: 'Enable hybrid post-quantum negotiation (true) to defend against Store Now, Decrypt Later attacks.',
  },
];

function isPureCommentLine(trimmed: string): boolean {
  return (
    trimmed.startsWith('#') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*')
  );
}

export function scanPolicyContent(content: string, fileName?: string): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, idx) => {
    const trimmed = lineText.trim();
    if (!trimmed || isPureCommentLine(trimmed)) {
      return;
    }

    // Strip trailing inline comments for # style configs when checking rules
    const codePart = lineText.replace(/\s+#.*$/, '');

    for (const rule of POLICY_RULES) {
      const match = rule.pattern.exec(codePart);
      if (match) {
        findings.push({
          line: idx + 1,
          column: (match.index ?? 0) + 1,
          ruleId: rule.id,
          cwe: rule.cwe,
          rule: rule.title,
          matchedText: match[0],
          severity: rule.severity,
          standard: rule.standard,
          fix: rule.fix,
          ...(fileName ? { file: fileName } : {}),
        });
      }
    }
  });

  return findings;
}
