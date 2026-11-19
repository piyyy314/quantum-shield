# Federal & Industry Compliance Mapping

This document maps QuantumShield Suite capabilities to U.S. federal quantum-readiness directives and cryptographic standards.

## 1. OMB Memorandum M-23-02 & NSM-10

| Mandate Requirement | QuantumShield Capability | Verification Artifact |
| :--- | :--- | :--- |
| Automated Cryptographic Discovery & Inventory | Workspace file scanner, live runtime OpenSSL probe, and custom asset registry | `POST /api/audit` JSON report |
| Prioritization via Data Shelf-Life & Migration Horizon | Interactive Mosca's Theorem `(X + Y) > Z` calculator & Asset Risk Matrix | `src/engine/moscaRisk.ts` |
| Machine-Readable Inventory Reporting | CycloneDX 1.5 Cryptographic Bill of Materials (CBOM) export | `src/engine/cbomBuilder.ts` |

## 2. NIST Post-Quantum Standards (FIPS 203, 204, 205)

- **FIPS 203 (ML-KEM):** `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`, plus IETF-aligned hybrid `X25519+ML-KEM-768`.
- **FIPS 204 (ML-DSA):** `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` keypair generation and sign/verify verification.
- **FIPS 205 (SLH-DSA):** `slh-dsa-sha2-128f`, `slh-dsa-sha2-256f` stateless hash-based signatures.

## 3. NSA CNSA 2.0 & NIST SP 800-131A Rev. 2

The static linter (`src/engine/policyScanner.ts`) flags disallowed and transitional primitives:

- **Disallowed (`CRITICAL`):** `MD5` (`CWE-328`), `SHA-1` (`CWE-328`), `DES/3DES/RC4` (`CWE-327`), `RSA < 2048` (`CWE-326`), `SSLv3 / TLS 1.0 / TLS 1.1` (`CWE-327`), classical `Diffie-Hellman` groups (`CWE-327`).
- **Transitional / Borderline (`HIGH` / `MEDIUM`):** `AES-128` (`CWE-326`, CNSA 2.0 mandates `AES-256`), `RSA-2048/3072/4096` (Shor-vulnerable), `Math.random()` (`CWE-338`), disabled hybrid PQC configuration flags.
