# QuantumShield Suite

**Document Classification:** Public / Open-Source Release (`Apache-2.0`)  
**Software Version:** `1.0.0`  
**Applicable Standards:** NIST FIPS 203, NIST FIPS 204, NIST FIPS 205, NIST IR 8547, NIST SP 800-131A Rev. 2, NSA CNSA 2.0, White House NSM-10, OMB Memorandum M-23-02, OWASP CycloneDX 1.5

---

## 1. Executive Summary & Operational Scope

**QuantumShield Suite** is a full-stack Post-Quantum Cryptography (PQC) governance, cryptographic inventory, live Transport Layer Security (TLS) assessment, and standards-compliant key generation platform. Designed in alignment with U.S. federal quantum-readiness mandates (**NSM-10** and **OMB M-23-02**), the system replaces static estimation models with live, verifiable cryptographic telemetry.

Organizations migrating toward **NIST FIPS 203 (ML-KEM)**, **NIST FIPS 204 (ML-DSA)**, **NIST FIPS 205 (SLH-DSA)**, and the **NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** require verifiable visibility into active runtime primitives, third-party dependencies, external TLS endpoints, and source/configuration vulnerabilities. QuantumShield Suite provides four integrated, non-simulated operational engines:

1. **Live Runtime & Workspace Discovery Engine:** Inspects the active Node.js / OpenSSL cryptographic provider, installed cryptographic dependencies, and workspace source/configuration files.
2. **Standards-Compliant PQC Key Synthesizer & Verifier:** Generates real cryptographic keypairs locally in the browser using `@noble/post-quantum` and Web Crypto CSPRNG (`crypto.getRandomValues`), computes SHA-256 fingerprints via Web Crypto `SubtleCrypto`, and executes live ML-KEM encapsulation/decapsulation and ML-DSA/SLH-DSA signature verification round-trips.
3. **Live Quantum TLS / X.509 Endpoint Scanner:** Executes real DNS lookups, Node.js `tls` handshakes, peer `X509Certificate` parsing, and OpenSSL `s_client` group inspection against public Fully Qualified Domain Names (FQDNs) with built-in Server-Side Request Forgery (SSRF) controls.
4. **CycloneDX 1.5 CBOM & Static CWE Policy Engine:** Parses real dependency manifests (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`) into CycloneDX 1.5 Cryptographic Bill of Materials (CBOM) JSON documents and audits code/configuration files against NIST SP 800-131A and MITRE CWE rules (`CWE-326`, `CWE-327`, `CWE-328`, `CWE-338`).

---

## 2. Regulatory & Standards Alignment Matrix

| Standard / Directive | Issuing Authority | Scope Within QuantumShield Suite | Implementation Status |
| :--- | :--- | :--- | :--- |
| **FIPS 203 (ML-KEM)** | NIST (Aug 2024) | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, and `X25519+ML-KEM-768` Hybrid keygen & KEM verification | **Implemented (`@noble/post-quantum`)** |
| **FIPS 204 (ML-DSA)** | NIST (Aug 2024) | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` keypair synthesis, PEM export, and signature sign/verify | **Implemented (`@noble/post-quantum`)** |
| **FIPS 205 (SLH-DSA)** | NIST (Aug 2024) | `SLH-DSA-SHA2-128f` and `SLH-DSA-SHA2-256f` stateless hash-based signatures | **Implemented (`@noble/post-quantum`)** |
| **CNSA 2.0** | NSA | Prioritizes Level 5 primitives (`ML-KEM-1024`, `ML-DSA-87`, `AES-256`, `SHA-384/512`) and tracks 2025–2033 milestones | **Enforced in Risk & Policy Engines** |
| **OMB M-23-02 / NSM-10** | White House / OMB / CISA | Automated cryptographic asset discovery, Mosca's Theorem `(X + Y) > Z` prioritization, and JSON audit export | **Implemented** |
| **NIST SP 800-131A Rev. 2** | NIST | Static detection of disallowed/deprecated primitives (`MD5`, `SHA-1`, `DES/3DES`, `RC4`, `RSA < 2048`) | **Implemented (`src/engine/policyScanner.ts`)** |
| **CycloneDX 1.5 (CBOM)** | OWASP | Machine-readable cryptographic bill of materials JSON export with UUIDv4 serial numbers | **Implemented (`src/engine/cbomBuilder.ts`)** |

---

## 3. System Architecture & Verification Guarantees

```text
+-----------------------------------------------------------------------------+
|                        Client UI (React 19 + Vite)                          |
|  - Executive Posture Overview     - Mosca's Theorem (X + Y > Z) Calculator  |
|  - Live Asset Risk Matrix         - In-Browser PQC Keygen & Round-Trip Test |
+--------------------------------------+--------------------------------------+
                                       | HTTPS / REST JSON (/api/*)
+--------------------------------------v--------------------------------------+
|                     Express API Server (server/app.ts)                      |
|  - /api/health        (Node.js & OpenSSL runtime inspection)                |
|  - /api/audit         (Workspace file scan, CBOM discovery, asset posture)  |
|  - /api/inventory     (Live asset registry CRUD + risk classification)      |
|  - /api/tls-scan      (SSRF-guarded live DNS + TLS + X.509 + OpenSSL probe) |
|  - /api/cbom[/parse]  (Live manifest analyzer -> CycloneDX 1.5 CBOM)        |
|  - /api/policy-scan   (Static CWE-326/327/328/338 & PQC rule engine)        |
+-----------------------------------------------------------------------------+
```

### Key Integrity Guarantees
- **Zero Synthetic / Simulated Results:** All TLS handshake grades, X.509 certificate fingerprints, dependency inventories, workspace file scans, and PQC keys/signatures are computed dynamically from live system inputs and cryptographic primitives.
- **Client-Side Private Key Isolation:** All generated ML-KEM, ML-DSA, and SLH-DSA private keys remain strictly in client browser memory and are never transmitted to any server endpoint.
- **SSRF Defense-in-Depth:** The `/api/tls-scan` endpoint enforces strict FQDN validation and blocks loopback (`127.0.0.0/8`, `::1`), RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and CGNAT (`100.64.0.0/10`) ranges by default.

---

## 4. Prerequisites, Installation & Operation

### 4.1 System Prerequisites
- **Node.js:** `>= 22.0.0` (verified on `v22.23.2`; native TypeScript execution supported)
- **npm:** `>= 10.0.0`
- **OpenSSL:** `>= 3.0.x` (optional CLI enhancement for TLS 1.3 ephemeral group reporting via `openssl s_client`)

### 4.2 Installation & Environment Configuration
```bash
git clone https://github.com/your-org/quantumshield-suite.git
cd quantumshield-suite
npm install
cp .env.example .env
```

Review `.env` variables prior to startup:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3000` | HTTP server listening port (`0.0.0.0:3000`) |
| `NODE_ENV` | `development` | `development` mounts Vite middleware; `production` serves `dist/` |
| `ALLOW_PRIVATE_TLS_SCAN` | `false` | Set to `true` only in isolated internal audits where scanning RFC 1918 targets is authorized |

### 4.3 Running Development & Production Builds
```bash
# Development (Express API + Vite HMR middleware on port 3000)
npm run dev

# Production Build & Server Execution
npm run build
NODE_ENV=production npm start
```

---

## 5. Quality Assurance, Linting & Automated Testing

All pull requests and public releases must pass strict TypeScript verification, unit/API/UI test suites, and production bundling:

```bash
# 1. Static TypeScript verification
npm run lint

# 2. Automated test suite (PQC round-trips, Mosca math, CWE rules, CBOM, Supertest API, React UI)
npm test

# 3. Production bundle verification
npm run build
```

---

## 6. REST API Reference

| Method & Path | Purpose | Request Payload |
| :--- | :--- | :--- |
| `GET /api/health` | Returns live Node.js, OpenSSL, FIPS mode, and cipher count | None |
| `POST /api/audit` | Runs a full workspace source scan, manifest CBOM extraction, and runtime audit | None |
| `GET /api/inventory` | Lists discovered runtime, workspace, TLS-scanned, and registered assets | None |
| `POST /api/inventory` | Evaluates and registers a cryptographic asset into live inventory | `{ name, system, algorithm, keySize, primitiveType, shelfLifeYears, migrationTimeMonths }` |
| `DELETE /api/inventory/:id` | Removes a user-registered or TLS-imported asset | URL param `:id` |
| `POST /api/tls-scan` | Performs live DNS lookup, TLS handshake, X.509 extraction, and PQC grading | `{ host: string, port?: number, recordInInventory?: boolean }` |
| `GET /api/cbom` | Generates CBOM entries from the active repository `package.json` | None |
| `POST /api/cbom/parse` | Parses external `package.json`, `requirements.txt`, `go.mod`, or `Cargo.toml` | `{ manifestType, content }` |
| `POST /api/policy-scan` | Executes static CWE-326/327/328/338 and PQC policy inspection | `{ content: string, fileName?: string }` |

---

## 7. Security Controls & Responsible Disclosure

- Security vulnerabilities must **not** be reported via public GitHub issues. Follow the coordinated disclosure procedures documented in [SECURITY.md](./SECURITY.md).
- Detailed architectural and federal control mappings are maintained in [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) and [docs/COMPLIANCE_MAPPING.md](./docs/COMPLIANCE_MAPPING.md).

---

## 8. Security Disclaimer & Authorized Use Notice

- **Authorized Assessment Only:** The Live Quantum TLS / X.509 Endpoint Scanner (`POST /api/tls-scan`) initiates active network connections and TLS handshakes against target hosts. Operators must only scan domains, endpoints, and infrastructure for which they hold explicit organizational authorization.
- **Cryptographic Validation Boundary:** Post-quantum key encapsulation and digital signature operations utilize `@noble/post-quantum` (pure TypeScript implementations aligned with NIST FIPS 203, FIPS 204, and FIPS 205). Software-only JavaScript/TypeScript execution is **not** FIPS 140-3 CMVP hardware-certified; regulated national security or federal production deployments requiring FIPS 140-3 validated cryptographic modules must integrate validated Hardware Security Modules (HSMs) or accredited cryptographic providers.
- **No Warranty & Compliance Advisory:** Risk ratings, Mosca's Theorem `(X + Y) > Z` timelines, and CycloneDX CBOM outputs are provided as engineering decision-support artifacts and do not constitute formal Authority to Operate (ATO) certification or legal compliance attestation. Software is provided **"AS IS"** without warranty of any kind under the Apache License, Version 2.0.

---

## 9. Governance & Licensing

- **License:** Distributed under the **Apache License, Version 2.0**. See [LICENSE](./LICENSE) for full legal terms.
- **Contributions:** See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
- **Release History:** See [CHANGELOG.md](./CHANGELOG.md).
