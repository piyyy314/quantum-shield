import type { AlgorithmProfile, MigrationMilestone } from '../types/quantum.ts';

/**
 * Authoritative public cryptographic standards and threat profiles
 * grounded in NIST FIPS 203/204/205 (August 2024), NIST SP 800-131A Rev 2,
 * NIST IR 8547, White House NSM-10, OMB M-23-02, and NSA CNSA 2.0.
 */
export const ALGORITHM_PROFILES: AlgorithmProfile[] = [
  {
    id: 'algo-rsa2048',
    name: 'RSA-2048',
    category: 'Asymmetric Key Exchange',
    quantumThreat: 'Shor',
    threatSeverity: 'CRITICAL',
    estimatedQubitsToBreak: '~4,098 Logical Qubits (Shor)',
    standardStatus: 'Sunset by 2030',
    pqcAlternative: 'ML-KEM-768 (FIPS 203)',
    description:
      'Relies on integer factorization. Solvable in polynomial time via Shor algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC). Vulnerable to Store Now, Decrypt Later (SNDL).',
    reference: 'NIST IR 8547 / SP 800-131A',
  },
  {
    id: 'algo-rsa4096',
    name: 'RSA-4096',
    category: 'Digital Signature',
    quantumThreat: 'Shor',
    threatSeverity: 'CRITICAL',
    estimatedQubitsToBreak: '~8,194 Logical Qubits (Shor)',
    standardStatus: 'Sunset by 2030',
    pqcAlternative: 'ML-DSA-87 (FIPS 204)',
    description:
      'Increasing modulus length only raises Shor circuit depth polynomially and does not provide long-term quantum resistance against fault-tolerant quantum computers.',
    reference: 'NIST IR 8547 / CNSA 2.0',
  },
  {
    id: 'algo-p256',
    name: 'ECDSA / ECDH P-256',
    category: 'Asymmetric Key Exchange',
    quantumThreat: 'Shor',
    threatSeverity: 'CRITICAL',
    estimatedQubitsToBreak: '~2,330 Logical Qubits (Roetteler et al.)',
    standardStatus: 'Sunset by 2030',
    pqcAlternative: 'ML-KEM-768 / ML-DSA-65',
    description:
      'Elliptic curve discrete logarithm breaks with fewer logical qubits than RSA-2048 via Shor period-finding.',
    reference: 'NIST IR 8547',
  },
  {
    id: 'algo-ed25519',
    name: 'Ed25519 / X25519',
    category: 'Digital Signature',
    quantumThreat: 'Shor',
    threatSeverity: 'CRITICAL',
    estimatedQubitsToBreak: '~2,330–2,500 Logical Qubits (Shor)',
    standardStatus: 'Sunset by 2030',
    pqcAlternative: 'X25519+ML-KEM-768 / ML-DSA-44',
    description:
      'High-speed Edwards/Montgomery curves remain strong against classical attackers and are widely used in hybrid PQC transitions, but standalone curves are broken by Shor algorithm.',
    reference: 'IETF draft-ietf-tls-hybrid-design',
  },
  {
    id: 'algo-aes128',
    name: 'AES-128',
    category: 'Symmetric Encryption',
    quantumThreat: 'Grover',
    threatSeverity: 'MEDIUM',
    estimatedQubitsToBreak: '~2^64 Quantum Queries (Grover)',
    standardStatus: 'Sunset by 2030',
    pqcAlternative: 'AES-256-GCM (CNSA 2.0)',
    description:
      'Grover quadratic search reduces exhaustive key search complexity quadratically. NSA CNSA 2.0 mandates 256-bit symmetric keys (AES-256) for long-term protection.',
    reference: 'NSA CNSA 2.0',
  },
  {
    id: 'algo-aes256',
    name: 'AES-256-GCM',
    category: 'Symmetric Encryption',
    quantumThreat: 'Grover',
    threatSeverity: 'COMPLIANT',
    estimatedQubitsToBreak: '~2^128 Quantum Operations',
    standardStatus: 'Safe (256-bit)',
    pqcAlternative: 'AES-256 (Compliant)',
    description:
      'Post-Grover effective security margin remains 128 bits. Approved for TOP SECRET under NSA CNSA 2.0.',
    reference: 'NSA CNSA 2.0 / FIPS 197',
  },
  {
    id: 'algo-sha384',
    name: 'SHA-384 / SHA-512 / SHA-3',
    category: 'Cryptographic Hash',
    quantumThreat: 'Grover',
    threatSeverity: 'COMPLIANT',
    estimatedQubitsToBreak: '>= 2^128 Quantum Operations',
    standardStatus: 'Safe (256-bit)',
    pqcAlternative: 'SHA-384 / SHA-512 (CNSA 2.0)',
    description:
      'SHA-384 and SHA-512 preserve high collision and preimage security margins against quantum search; mandated by NSA CNSA 2.0.',
    reference: 'NSA CNSA 2.0 / FIPS 180-4',
  },
  {
    id: 'algo-ml-kem',
    name: 'ML-KEM (CRYSTALS-Kyber)',
    category: 'Post-Quantum KEM',
    quantumThreat: 'Standardized',
    threatSeverity: 'COMPLIANT',
    estimatedQubitsToBreak: 'Lattice M-LWE (Resistant)',
    standardStatus: 'NIST Standard (FIPS 203)',
    pqcAlternative: 'ML-KEM-768 / ML-KEM-1024',
    description:
      'Module-Lattice-Based Key-Encapsulation Mechanism standardized by NIST in FIPS 203 (August 13, 2024). ML-KEM-1024 is required by NSA CNSA 2.0.',
    reference: 'NIST FIPS 203',
  },
  {
    id: 'algo-ml-dsa',
    name: 'ML-DSA (CRYSTALS-Dilithium)',
    category: 'Post-Quantum Signature',
    quantumThreat: 'Standardized',
    threatSeverity: 'COMPLIANT',
    estimatedQubitsToBreak: 'Lattice M-LWE / M-SIS (Resistant)',
    standardStatus: 'NIST Standard (FIPS 204)',
    pqcAlternative: 'ML-DSA-65 / ML-DSA-87',
    description:
      'Module-Lattice-Based Digital Signature Algorithm standardized by NIST in FIPS 204 (August 13, 2024). ML-DSA-87 is selected for NSA CNSA 2.0.',
    reference: 'NIST FIPS 204',
  },
  {
    id: 'algo-slh-dsa',
    name: 'SLH-DSA (SPHINCS+)',
    category: 'Post-Quantum Signature',
    quantumThreat: 'Standardized',
    threatSeverity: 'COMPLIANT',
    estimatedQubitsToBreak: 'Hash-Based (Resistant)',
    standardStatus: 'NIST Standard (FIPS 205)',
    pqcAlternative: 'SLH-DSA-SHA2-128f / 256f',
    description:
      'Stateless Hash-Based Digital Signature Algorithm standardized by NIST in FIPS 205 (August 13, 2024). Relies strictly on hash function assumptions.',
    reference: 'NIST FIPS 205',
  },
];

export const MIGRATION_MILESTONES: MigrationMilestone[] = [
  {
    year: '2022',
    title: 'NSM-10 & OMB M-23-02 Inventory Mandate',
    organization: 'White House / OMB / CISA',
    mandate: 'Federal agencies ordered to establish cryptographic inventories and prioritize PQC migration.',
    status: 'Completed',
    impactSummary: 'Initiated annual federal cryptographic inventory reporting and high-value asset prioritization.',
  },
  {
    year: '2024',
    title: 'FIPS 203, 204, 205 Standardization',
    organization: 'NIST (U.S. Dept. of Commerce)',
    mandate: 'Publication of ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).',
    status: 'Completed',
    impactSummary: 'Codified primary post-quantum key encapsulation and digital signature standards for immediate adoption.',
  },
  {
    year: '2025–2027',
    title: 'CNSA 2.0 Software & Firmware Transition',
    organization: 'NSA (National Security Agency)',
    mandate: 'New software, firmware, and networking equipment for National Security Systems support CNSA 2.0.',
    status: 'In Progress',
    impactSummary: 'Software and firmware signing transitions to LMS/XMSS or ML-DSA-87; vendors ship hybrid PQC TLS.',
  },
  {
    year: '2030',
    title: 'Classical Asymmetric Deprecation Target',
    organization: 'NIST IR 8547 / NSA CNSA 2.0',
    mandate: 'Deprecated 112-bit classical asymmetric schemes disallowed; exclusive PQC required for new NSS procurements.',
    status: 'Upcoming',
    impactSummary: 'RSA-2048 and classical ECC phased out across federal and regulated critical infrastructure.',
  },
  {
    year: '2033–2035',
    title: 'Full Federal & CNSA 2.0 Compliance',
    organization: 'NSA / NSM-10 Federal Deadline',
    mandate: 'Complete transition to quantum-resistant cryptography across federal and national security systems.',
    status: 'Upcoming',
    impactSummary: 'Zero non-quantum-resistant public-key algorithms permitted in regulated production environments.',
  },
];
