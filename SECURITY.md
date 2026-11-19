# Security Policy

## Supported Versions

| Version | Supported | Security Baseline |
| :--- | :--- | :--- |
| `1.0.x` | Yes | NIST FIPS 203 / 204 / 205, CNSA 2.0 |
| `< 1.0.0` | No | Pre-release prototypes |

## Reporting a Vulnerability

**Do not open public GitHub Issues for security vulnerabilities.**

Please report security findings privately through GitHub Security Advisories or by contacting the project security maintainers with:
1. Affected component or endpoint (e.g., `/api/tls-scan`, `src/engine/pqcCrypto.ts`).
2. Minimal reproduction steps or proof of concept.
3. Estimated severity and CWE classification, if known.

We target initial acknowledgment within **48 hours** and coordinated remediation disclosure within **14–30 days** depending on severity.

## Threat Model & Hardening Controls

- **Server-Side Request Forgery (SSRF):** `/api/tls-scan` enforces strict FQDN validation and rejects loopback (`127.0.0.0/8`, `::1`), RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and CGNAT (`100.64.0.0/10`) targets unless `ALLOW_PRIVATE_TLS_SCAN=true` is explicitly configured in an isolated audit environment.
- **Command Injection Prevention:** OpenSSL probing uses `child_process.execFile` with explicit argument arrays and never invokes a shell.
- **Private Key Isolation:** PQC keypairs generated in the UI are created locally inside the browser via `@noble/post-quantum` and Web Crypto CSPRNG; secret key material is never transmitted to the server.
- **Cryptographic Boundaries:** `@noble/post-quantum` provides audited, constant-time JavaScript/TypeScript implementations of FIPS 203/204/205; however, deployments requiring FIPS 140-3 Level 1–4 hardware certification must pair the suite with a validated HSM or FIPS 140-3 module.
