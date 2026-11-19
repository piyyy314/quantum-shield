# System Architecture

## 1. Overview

QuantumShield Suite uses a unified TypeScript full-stack architecture:

- **Frontend (`src/`):** React 19 + Tailwind CSS v4 Single Page Application bundled via Vite 6.
- **Cryptographic & Analysis Engines (`src/engine/`):** Shared pure-TypeScript modules consumed by the client UI, backend API, and Vitest test suite.
- **Backend API (`server.ts`, `server/app.ts`):** Express 4 HTTP server executing live workspace audits, manifest parsing, and SSRF-guarded TLS/X.509 network probes.

## 2. Module Responsibilities

| Module | Responsibility | External Dependencies |
| :--- | :--- | :--- |
| `src/engine/pqcCrypto.ts` | FIPS 203/204/205 & Hybrid KEM keygen, PEM encoding, SHA-256 fingerprinting, KEM/signature verification | `@noble/post-quantum`, Web Crypto API |
| `src/engine/moscaRisk.ts` | Mosca's Theorem `(X + Y) > Z` math, primitive risk classification, TLS posture scoring | None (pure TypeScript) |
| `src/engine/policyScanner.ts` | Static cryptographic CWE & NIST SP 800-131A rule evaluation with comment immunity | None (pure TypeScript) |
| `src/engine/cbomBuilder.ts` | `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml` parser and CycloneDX 1.5 JSON serializer | Web Crypto `randomUUID` |
| `server/app.ts` | Express API factory (`createApp`), DNS/TLS/OpenSSL live inspection, workspace file scanner | `node:tls`, `node:dns`, `node:crypto`, `node:fs` |
| `server.ts` | Production static server / Vite dev middleware runner on `0.0.0.0:3000` | `express`, `vite` |

## 3. Data Flow Principles

1. **Workspace & Runtime Discovery:** On initialization and on every `Run Audit` trigger (`POST /api/audit`), `server/app.ts` inspects the active Node.js `process.versions.openssl`, enumerates supported ciphers, parses `/package.json`, and scans repository files via `scanPolicyContent`.
2. **Live TLS Inspection:** `POST /api/tls-scan` validates the hostname FQDN, checks resolved IPs against RFC 1918 / loopback / link-local ranges, initiates a live `tls.connect` socket with `getPeerX509Certificate()`, optionally queries `openssl s_client -brief` via `execFile` (no shell), and passes telemetry to `evaluateTlsPosture`.
3. **In-Browser PQC Operations:** All key synthesis (`generatePqcKeyPair`), KEM encapsulation/decapsulation (`verifyKemRoundTrip`), and signature operations (`verifySignatureRoundTrip`) execute strictly within the client browser runtime.
