import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp, isPrivateOrReservedIp, validateScanTarget } from '../server/app.ts';

describe('QuantumShield Express API Integration Tests', () => {
  const app = createApp({ rootDir: process.cwd() });

  it('GET /api/health returns live Node and OpenSSL runtime details', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.runtime.nodeVersion).toMatch(/^v\d+/);
    expect(res.body.runtime.opensslVersion).toBeTruthy();
    expect(res.body.runtime.cipherCount).toBeGreaterThan(0);
  });

  it('GET /api/cbom reads real workspace package.json dependencies', async () => {
    const res = await request(app).get('/api/cbom');
    expect(res.status).toBe(200);
    const components = res.body.entries.map((e: { component: string }) => e.component);
    expect(components).toContain('@noble/post-quantum');
  });

  it('POST /api/inventory registers and deletes a custom cryptographic asset', async () => {
    const createRes = await request(app).post('/api/inventory').send({
      name: 'API Auth Signing Key',
      system: 'Identity Service',
      algorithm: 'RSA-2048',
      keySize: 2048,
      primitiveType: 'Asymmetric',
      shelfLifeYears: 10,
      migrationTimeMonths: 12,
    });
    expect(createRes.status).toBe(201);
    expect(createRes.body.quantumRisk).toBe('CRITICAL');

    const delRes = await request(app).delete(`/api/inventory/${createRes.body.id}`);
    expect(delRes.status).toBe(200);
  });

  it('POST /api/policy-scan detects weak cryptography in submitted code', async () => {
    const res = await request(app).post('/api/policy-scan').send({
      fileName: 'nginx.conf',
      content: 'ssl_protocols TLSv1.0;\nhash = "md5";',
    });
    expect(res.status).toBe(200);
    expect(res.body.findings.length).toBe(2);
  });

  it('POST /api/audit scans the live workspace and returns audit telemetry', async () => {
    const res = await request(app).post('/api/audit');
    expect(res.status).toBe(200);
    expect(res.body.assetsDiscovered).toBeGreaterThanOrEqual(3);
    expect(res.body.workspaceFilesScanned).toBeGreaterThan(0);
  });

  it('enforces SSRF protection and strict hostname validation on TLS targets', async () => {
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
    expect(isPrivateOrReservedIp('10.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false);

    expect(() => validateScanTarget('localhost', 443)).toThrow();
    expect(() => validateScanTarget('example.com; rm -rf /', 443)).toThrow();

    const badRes = await request(app).post('/api/tls-scan').send({ host: '127.0.0.1', port: 443 });
    expect(badRes.status).toBe(400);
  });
});
