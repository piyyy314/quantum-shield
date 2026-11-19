# Contributing to QuantumShield Suite

We welcome community contributions that strengthen post-quantum cryptographic visibility, standards compliance, and test coverage.

## Development Workflow

1. **Fork & Branch:** Create a descriptive feature or fix branch from `main` (e.g., `feat/cbom-gradle-parser`, `fix/tls-san-parsing`).
2. **Install & Verify Baseline:**
   ```bash
   npm install
   npm run lint
   npm test
   npm run build
   ```
3. **Coding Standards:**
   - Strict TypeScript (`tsc --noEmit` must pass with zero warnings/errors).
   - **No Fake Simulations:** All scanners, cryptographic generators, and telemetry endpoints must operate on real data and real cryptographic primitives.
   - All security-critical changes (SSRF guards, regex rules, cryptographic routines) require accompanying Vitest unit/integration tests in `tests/`.
   - Server modules imported by Node.js native execution (`node server.ts`) must use explicit `.ts` extensions and `import type` for type-only imports.
4. **Pull Request Checklist:**
   - Complete the Pull Request template.
   - Ensure CI checks (`lint`, `test`, `build`) pass cleanly.
   - Update `README.md` or `docs/` if API contracts or compliance mappings change.

## Licensing

By submitting a pull request, you agree that your contributions are licensed under the **Apache License, Version 2.0**.
