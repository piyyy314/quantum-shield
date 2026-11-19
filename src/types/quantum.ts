export type NavigationSection = 'overview' | 'risk-analysis' | 'security-modules';
export type SecuritySubModule = 'key-generator' | 'tls-scanner' | 'cbom' | 'policy-scanner';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'COMPLIANT';

export interface CryptoAsset {
  id: string;
  name: string;
  system: string;
  algorithm: string;
  keySize: number;
  primitiveType: 'Asymmetric' | 'Symmetric' | 'Hash' | 'PQC Hybrid' | 'PQC Native';
  quantumRisk: RiskLevel;
  shelfLifeYears: number;
  migrationTimeMonths: number;
  recommendedPQC: string;
  notes: string;
}

export interface AlgorithmProfile {
  id: string;
  name: string;
  category: 'Asymmetric Key Exchange' | 'Digital Signature' | 'Symmetric Encryption' | 'Cryptographic Hash' | 'Post-Quantum KEM' | 'Post-Quantum Signature';
  quantumThreat: 'Shor' | 'Grover' | 'None' | 'Standardized';
  threatSeverity: RiskLevel;
  estimatedQubitsToBreak: string;
  standardStatus: 'Deprecated / High Risk' | 'Sunset by 2030' | 'Safe (256-bit)' | 'NIST Standard (FIPS 203)' | 'NIST Standard (FIPS 204)' | 'NIST Standard (FIPS 205)' | 'NIST Standard (FIPS 203/204/205)';
  pqcAlternative: string;
  description: string;
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
}

export interface TLSScanResult {
  host: string;
  port: number;
  ip: string;
  tlsVersion: string;
  keyExchange: string;
  signatureAlgorithm: string;
  quantumSafeGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
  quantumSafetyScore: number;
  isHybridPQC: boolean;
  recommendations: string[];
}
