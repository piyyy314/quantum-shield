import type { CBOMEntry, RiskLevel } from '../types/quantum.ts';

interface CryptoPackageSignature {
  algorithm: string;
  purpose: string;
  riskLevel: RiskLevel;
  nistStandard: string;
  license: string;
}

const KNOWN_CRYPTO_PACKAGES: Record<string, CryptoPackageSignature> = {
  '@noble/post-quantum': {
    algorithm: 'ML-KEM (512/768/1024), ML-DSA (44/65/87), SLH-DSA, X25519+ML-KEM-768',
    purpose: 'NIST Post-Quantum KEM & Signature Primitives',
    riskLevel: 'COMPLIANT',
    nistStandard: 'FIPS 203 / 204 / 205',
    license: 'MIT',
  },
  '@noble/curves': {
    algorithm: 'secp256k1, Ed25519, P-256, P-384',
    purpose: 'Classical Elliptic Curve Cryptography',
    riskLevel: 'HIGH',
    nistStandard: 'FIPS 186-5 (Shor-Vulnerable)',
    license: 'MIT',
  },
  '@noble/hashes': {
    algorithm: 'SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2/3',
    purpose: 'Cryptographic Hashing & KDF',
    riskLevel: 'COMPLIANT',
    nistStandard: 'FIPS 180-4 / FIPS 202',
    license: 'MIT',
  },
  'liboqs': {
    algorithm: 'ML-KEM, ML-DSA, SLH-DSA, Falcon',
    purpose: 'Open Quantum Safe C/Native Library',
    riskLevel: 'COMPLIANT',
    nistStandard: 'FIPS 203 / 204 / 205',
    license: 'MIT',
  },
  'oqs': {
    algorithm: 'ML-KEM, ML-DSA, SLH-DSA',
    purpose: 'Open Quantum Safe Language Bindings',
    riskLevel: 'COMPLIANT',
    nistStandard: 'FIPS 203 / 204 / 205',
    license: 'MIT',
  },
  'pqcrypto': {
    algorithm: 'ML-KEM, ML-DSA, SLH-DSA',
    purpose: 'Post-Quantum Cryptography Crate',
    riskLevel: 'COMPLIANT',
    nistStandard: 'FIPS 203 / 204 / 205',
    license: 'MIT / Apache-2.0',
  },
  'jose': {
    algorithm: 'RS256, ES256, EdDSA, ECDH-ES, AES-GCM',
    purpose: 'JOSE / JWT / JWE / JWS Signing & Encryption',
    riskLevel: 'HIGH',
    nistStandard: 'Pre-Quantum Asymmetric (RFC 7518)',
    license: 'MIT',
  },
  'jsonwebtoken': {
    algorithm: 'RS256, ES256, HS256',
    purpose: 'JSON Web Token Signing & Verification',
    riskLevel: 'HIGH',
    nistStandard: 'Pre-Quantum RSA/ECDSA',
    license: 'MIT',
  },
  'node-forge': {
    algorithm: 'RSA, AES, DES, MD5, SHA-1, X.509',
    purpose: 'Pure JS TLS & PKI Toolkit',
    riskLevel: 'CRITICAL',
    nistStandard: 'Legacy Classical (Includes MD5/SHA1/RSA)',
    license: 'BSD-3-Clause',
  },
  'crypto-js': {
    algorithm: 'AES, DES, 3DES, RC4, MD5, SHA-1, SHA-256',
    purpose: 'Legacy Browser Symmetric & Hash Library',
    riskLevel: 'HIGH',
    nistStandard: 'Legacy / Unmaintained (Migrate to WebCrypto)',
    license: 'MIT',
  },
  'elliptic': {
    algorithm: 'ECDSA, ECDH (secp256k1, P-256)',
    purpose: 'Elliptic Curve Signatures & Key Exchange',
    riskLevel: 'CRITICAL',
    nistStandard: 'Pre-Quantum ECC (Shor-Vulnerable)',
    license: 'MIT',
  },
  'bcryptjs': {
    algorithm: 'Blowfish Eksblowfish Password KDF',
    purpose: 'Password Hashing',
    riskLevel: 'LOW',
    nistStandard: 'Symmetric KDF (Grover-Resilient)',
    license: 'MIT',
  },
  'argon2': {
    algorithm: 'Argon2id / Argon2i Memory-Hard KDF',
    purpose: 'Password Hashing & Key Derivation',
    riskLevel: 'COMPLIANT',
    nistStandard: 'RFC 9106 / NIST SP 800-63B',
    license: 'MIT',
  },
  'tweetnacl': {
    algorithm: 'Curve25519, Ed25519, XSalsa20-Poly1305',
    purpose: 'Authenticated Encryption & Signatures',
    riskLevel: 'HIGH',
    nistStandard: 'Pre-Quantum Asymmetric (Curve25519)',
    license: 'Unlicense',
  },
  'cryptography': {
    algorithm: 'AES-GCM, ChaCha20, RSA, ECDSA, Ed25519, X25519',
    purpose: 'Python Cryptographic Primitives & X.509',
    riskLevel: 'MEDIUM',
    nistStandard: 'Classical + OpenSSL 3.x Provider Ready',
    license: 'Apache-2.0 / BSD-3-Clause',
  },
  'pycryptodome': {
    algorithm: 'AES, RSA, ECC, SHA-2/3, Salsa20',
    purpose: 'Python Cryptographic Library',
    riskLevel: 'MEDIUM',
    nistStandard: 'Classical Primitives (No Native FIPS 203/204)',
    license: 'BSD-2-Clause',
  },
  'golang.org/x/crypto': {
    algorithm: 'ChaCha20-Poly1305, Ed25519, Curve25519, SSH, Argon2',
    purpose: 'Go Supplementary Cryptography',
    riskLevel: 'HIGH',
    nistStandard: 'Classical (Go 1.24+ stdlib adds crypto/mlkem)',
    license: 'BSD-3-Clause',
  },
  'rustls': {
    algorithm: 'TLS 1.3 (X25519MLKEM768 with aws-lc-rs)',
    purpose: 'Memory-Safe TLS Stack',
    riskLevel: 'LOW',
    nistStandard: 'Hybrid PQC Ready (RFC 8446 + ML-KEM)',
    license: 'Apache-2.0 / ISC / MIT',
  },
  'ring': {
    algorithm: 'AES-GCM, ChaCha20, ECDSA, Ed25519, X25519, RSA',
    purpose: 'Rust Safe Cryptography Primitives',
    riskLevel: 'HIGH',
    nistStandard: 'Classical Asymmetric Primitives',
    license: 'ISC / OpenSSL',
  },
  'express': {
    algorithm: 'Node.js HTTP/TLS Transport Consumer',
    purpose: 'Web Application & API Server Framework',
    riskLevel: 'LOW',
    nistStandard: 'Delegates TLS to Node.js OpenSSL',
    license: 'MIT',
  },
  '@google/genai': {
    algorithm: 'HTTPS / TLS 1.3 Client Transport',
    purpose: 'External API SDK Transport',
    riskLevel: 'LOW',
    nistStandard: 'Relies on Host TLS Stack',
    license: 'Apache-2.0',
  },
};

export function classifyDependency(
  name: string,
  version: string,
  sourceManifest: string,
  index: number
): CBOMEntry | null {
  const normalized = name.toLowerCase().trim();
  const matchedKey = Object.keys(KNOWN_CRYPTO_PACKAGES).find(
    (k) => normalized === k || normalized.endsWith(`/${k}`)
  );

  if (matchedKey) {
    const sig = KNOWN_CRYPTO_PACKAGES[matchedKey];
    return {
      id: `cbom-${index}-${normalized.replace(/[^a-z0-9]/g, '-')}`,
      component: name,
      version,
      algorithm: sig.algorithm,
      purpose: sig.purpose,
      riskLevel: sig.riskLevel,
      nistStandard: sig.nistStandard,
      license: sig.license,
      sourceManifest,
    };
  }

  // Heuristic match for unlisted crypto/auth/tls packages
  if (/(crypto|cipher|tls|ssl|jwt|oauth|pkcs|x509|pgp|gpg|pqc|kyber|dilithium|mlkem|ssh|bcrypt|scrypt|hash)/i.test(normalized)) {
    return {
      id: `cbom-${index}-${normalized.replace(/[^a-z0-9]/g, '-')}`,
      component: name,
      version,
      algorithm: 'Unverified Cryptographic Dependency (Manual Review)',
      purpose: 'Cryptographic / Security Package',
      riskLevel: 'MEDIUM',
      nistStandard: 'Requires Algorithm Audit',
      license: 'See Upstream Manifest',
      sourceManifest,
    };
  }

  return null;
}

export function parsePackageJsonManifest(rawJson: string, sourceLabel = 'package.json'): CBOMEntry[] {
  const parsed = JSON.parse(rawJson) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const allDeps: Array<[string, string]> = [
    ...Object.entries(parsed.dependencies ?? {}),
    ...Object.entries(parsed.devDependencies ?? {}),
  ];

  const entries: CBOMEntry[] = [];
  allDeps.forEach(([name, version], idx) => {
    const entry = classifyDependency(name, version.replace(/^[\^~]/, ''), sourceLabel, idx + 1);
    if (entry) {
      entries.push(entry);
    }
  });

  return entries;
}

export function parseTextManifest(rawText: string, manifestType: 'requirements.txt' | 'go.mod' | 'Cargo.toml'): CBOMEntry[] {
  const entries: CBOMEntry[] = [];
  const lines = rawText.split(/\r?\n/);

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) return;

    let name = '';
    let version = 'unspecified';

    if (manifestType === 'requirements.txt') {
      const m = /^([a-zA-Z0-9._-]+)\s*(?:==|>=|<=|~=)?\s*([a-zA-Z0-9.*_-]+)?/.exec(line);
      if (m) {
        name = m[1];
        version = m[2] || 'latest';
      }
    } else if (manifestType === 'go.mod') {
      const cleaned = line.replace(/^require\s+/, '');
      const m = /^([^\s]+)\s+(v[^\s]+)/.exec(cleaned);
      if (m) {
        name = m[1];
        version = m[2];
      }
    } else if (manifestType === 'Cargo.toml') {
      const m = /^([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/.exec(line);
      if (m) {
        name = m[1];
        version = m[2] || m[3] || 'unspecified';
      }
    }

    if (name) {
      const entry = classifyDependency(name, version, manifestType, idx + 1);
      if (entry) {
        entries.push(entry);
      }
    }
  });

  return entries;
}

export function buildCycloneDxCbom(entries: CBOMEntry[], appName = 'QuantumShield Suite', appVersion = '1.0.0') {
  const uuid =
    typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(16)}-4000-8000-000000000000`;

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${uuid}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'QuantumShield Suite',
          name: 'quantumshield-cbom-engine',
          version: appVersion,
        },
      ],
      component: {
        type: 'application',
        name: appName,
        version: appVersion,
      },
    },
    components: entries.map((c) => ({
      type: 'library',
      name: c.component,
      version: c.version,
      purl: `pkg:generic/${encodeURIComponent(c.component)}@${encodeURIComponent(c.version)}`,
      licenses: c.license ? [{ license: { name: c.license } }] : undefined,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: c.algorithm,
          nistStandard: c.nistStandard,
          quantumRiskLevel: c.riskLevel,
          sourceManifest: c.sourceManifest,
        },
      },
    })),
  };
}
