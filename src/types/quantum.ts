export type NavigationSection = 'overview' | 'risk-analysis' | 'security-modules';
export type SecuritySubModule = 'key-generator' | 'tls-scanner' | 'cbom' | 'policy-scanner';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'COMPLIANT';

export type PrimitiveCategory =
  | 'Asymmetric'
  | 'Symmetric'
  | 'Hash'
  | 'PQC Hybrid'
  | 'PQC Native';

export interface CryptoAsset {
  id: string;
  name: string;
  system: string;
  algorithm: string;
  keySize: number;
  primitiveType: PrimitiveCategory;
  quantumRisk: RiskLevel;
  shelfLifeYears: number;
  migrationTimeMonths: number;
  recommendedPQC: string;
  notes: string;
  source: 'runtime' | 'workspace' | 'tls-scan' | 'manual';
  discoveredAt: string;
}

export interface AlgorithmProfile {
  id: string;
  name: string;
  category:
    | 'Asymmetric Key Exchange'
    | 'Digital Signature'
    | 'Symmetric Encryption'
    | 'Cryptographic Hash'
    | 'Post-Quantum KEM'
    | 'Post-Quantum Signature';
  quantumThreat: 'Shor' | 'Grover' | 'None' | 'Standardized';
  threatSeverity: RiskLevel;
  estimatedQubitsToBreak: string;
  standardStatus:
    | 'Deprecated / Disallowed'
    | 'Sunset by 2030'
    | 'Safe (256-bit)'
    | 'NIST Standard (FIPS 203)'
    | 'NIST Standard (FIPS 204)'
    | 'NIST Standard (FIPS 205)';
  pqcAlternative: string;
  description: string;
  reference: string;
}

export interface MigrationMilestone {
  year: string;
  title: string;
  organization: string;
  mandate: string;
  status: 'Completed' | 'In Progress' | 'Upcoming';
  impactSummary: string;
}

export interface CBOMEntry {
  id: string;
  component: string;
  version: string;
  algorithm: string;
  purpose: string;
  riskLevel: RiskLevel;
  nistStandard: string;
  license: string;
  sourceManifest: string;
}

export interface TLSCertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  publicKeyType: string;
  publicKeyBits: number | null;
  fingerprint256: string;
  subjectAltNames: string[];
}

export interface TLSScanResult {
  host: string;
  port: number;
  ip: string;
  tlsVersion: string;
  cipherSuite: string;
  keyExchange: string;
  signatureAlgorithm: string;
  quantumSafeGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
  quantumSafetyScore: number;
  isHybridPQC: boolean;
  latencyMs: number;
  scannedAt: string;
  certificate: TLSCertificateInfo | null;
  recommendations: string[];
}

export interface PolicyFinding {
  line: number;
  column: number;
  ruleId: string;
  cwe: string;
  rule: string;
  matchedText: string;
  severity: RiskLevel;
  standard: string;
  fix: string;
  file?: string;
}

export interface RuntimeEnvironmentInfo {
  nodeVersion: string;
  opensslVersion: string;
  cipherCount: number;
  tls13Supported: boolean;
  fipsMode: boolean;
  platform: string;
  timestamp: string;
}

export interface AuditSummary {
  auditId: string;
  auditedAt: string;
  runtime: RuntimeEnvironmentInfo;
  assetsDiscovered: number;
  cbomComponentsCount: number;
  workspaceFilesScanned: number;
  workspaceFindings: PolicyFinding[];
  assets: CryptoAsset[];
  cbomEntries: CBOMEntry[];
}
