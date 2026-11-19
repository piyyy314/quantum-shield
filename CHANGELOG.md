# Changelog

All notable changes to **QuantumShield Suite** will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-19

### Added
- **Real Post-Quantum Cryptography Engine (`src/engine/pqcCrypto.ts`):** Integrated `@noble/post-quantum` for genuine NIST FIPS 203 (`ML-KEM-512/768/1024`), hybrid (`X25519+ML-KEM-768`), NIST FIPS 204 (`ML-DSA-44/65/87`), and NIST FIPS 205 (`SLH-DSA-SHA2-128f/256f`) key generation, Web Crypto SHA-256 fingerprinting, PEM export, and interactive KEM/signature round-trip verification.
- **Full-Stack Express Server (`server.ts`, `server/app.ts`):** Added `/api/health`, `/api/audit`, `/api/inventory`, `/api/tls-scan`, `/api/cbom`, `/api/cbom/parse`, and `/api/policy-scan`.
- **Live TLS / X.509 Scanner:** Real DNS lookup, Node.js `tls.connect` handshake, peer `X509Certificate` parsing, OpenSSL `s_client` group inspection, deterministic grading, and SSRF IP blocking.
- **CycloneDX 1.5 CBOM Engine (`src/engine/cbomBuilder.ts`):** Live `package.json` dependency discovery plus parser support for `requirements.txt`, `go.mod`, and `Cargo.toml`.
- **Static CWE Cryptographic Linter (`src/engine/policyScanner.ts`):** Live workspace file scanner and snippet/file auditor mapped to `CWE-326`, `CWE-327`, `CWE-328`, and `CWE-338`.
- **Automated Test Suite & CI:** Added Vitest unit, integration (`supertest`), and React UI tests alongside GitHub Actions CI, Apache-2.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and government-standard documentation.

### Fixed
- Eliminated all simulated/mock cryptographic datasets and hardcoded host results.
- Corrected "Mosley's Theorem" typo to **Mosca's Theorem** and removed raw LaTeX notation in the UI.
- Fixed zero-asset division (`NaN%`), invalid Tailwind border class (`border-slate-850`), toast timer leak, collapsed sidebar indentation, and `Escape` key handling in search.
