import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  isPrivateOrReservedIp,
  validateScanTarget,
  performLiveTlsScan,
} from '../server/app.ts';

const execFileAsync = promisify(execFile);

describe('TLS Scanner Logic & SSRF Defense Unit/Integration Suite', () => {
  describe('validateScanTarget', () => {
    it('normalizes valid FQDNs and defaults port to 443', () => {
      expect(validateScanTarget('NIST.GOV', undefined)).toEqual({ host: 'nist.gov', port: 443 });
      expect(validateScanTarget('https://Cloudflare.com/docs', 8443)).toEqual({
        host: 'cloudflare.com',
        port: 8443,
      });
      expect(validateScanTarget('http://api.example.org:8080/health', 443)).toEqual({
        host: 'api.example.org',
        port: 443,
      });
    });

    it('rejects non-string, malformed, single-label, IP literals, and injection payloads', () => {
      expect(() => validateScanTarget(12345, 443)).toThrow();
      expect(() => validateScanTarget('', 443)).toThrow();
      expect(() => validateScanTarget('localhost', 443)).toThrow();
      expect(() => validateScanTarget('127.0.0.1', 443)).toThrow();
      expect(() => validateScanTarget('example.com; rm -rf /', 443)).toThrow();
      expect(() => validateScanTarget('-badhost.example.com', 443)).toThrow();
    });

    it('validates TCP port boundaries strictly (1..65535)', () => {
      expect(validateScanTarget('example.com', 1).port).toBe(1);
      expect(validateScanTarget('example.com', 65535).port).toBe(65535);
      expect(() => validateScanTarget('example.com', 0)).toThrow();
      expect(() => validateScanTarget('example.com', 65536)).toThrow();
      expect(() => validateScanTarget('example.com', -443)).toThrow();
      expect(() => validateScanTarget('example.com', 443.5)).toThrow();
    });
  });

  describe('isPrivateOrReservedIp (SSRF Protection)', () => {
    it('blocks all private, loopback, link-local, CGNAT, and multicast IPv4 ranges', () => {
      const blockedIpv4 = [
        '127.0.0.1',
        '127.255.255.254',
        '10.0.0.1',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.1.1',
        '169.254.169.254',
        '100.64.0.1',
        '100.127.255.254',
        '0.0.0.0',
        '224.0.0.1',
      ];
      for (const ip of blockedIpv4) {
        expect(isPrivateOrReservedIp(ip)).toBe(true);
      }
    });

    it('allows routable public IPv4 addresses', () => {
      const publicIpv4 = ['1.1.1.1', '8.8.8.8', '172.32.0.1', '192.169.1.10', '93.184.216.34'];
      for (const ip of publicIpv4) {
        expect(isPrivateOrReservedIp(ip)).toBe(false);
      }
    });

    it('blocks loopback, link-local, ULA, and IPv4-mapped private IPv6 addresses', () => {
      const blockedIpv6 = [
        '::1',
        '::',
        'fe80::1',
        'fc00::1',
        'fd12:3456:789a::1',
        '::ffff:127.0.0.1',
        '::ffff:169.254.169.254',
        '::ffff:10.0.0.5',
      ];
      for (const ip of blockedIpv6) {
        expect(isPrivateOrReservedIp(ip)).toBe(true);
      }
      expect(isPrivateOrReservedIp('2606:4700:4700::1111')).toBe(false);
      expect(isPrivateOrReservedIp('not-an-ip')).toBe(true);
    });
  });

  describe('performLiveTlsScan against ephemeral TLS 1.3 server', () => {
    let tmpDir: string;
    let server: tls.Server;
    let serverPort: number;
    const prevAllowPrivate = process.env.ALLOW_PRIVATE_TLS_SCAN;

    beforeAll(async () => {
      tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qshield-tls-test-'));
      const keyPath = path.join(tmpDir, 'key.pem');
      const certPath = path.join(tmpDir, 'cert.pem');

      await execFileAsync('openssl', [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:prime256v1',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-days',
        '30',
        '-nodes',
        '-subj',
        '/CN=tls-unit-test.example.com',
      ]);

      const [key, cert] = await Promise.all([
        fs.readFile(keyPath, 'utf8'),
        fs.readFile(certPath, 'utf8'),
      ]);

      server = tls.createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, (socket) => {
        socket.end();
      });

      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address();
          serverPort = typeof addr === 'object' && addr ? addr.port : 0;
          resolve();
        });
      });
    });

    afterAll(async () => {
      process.env.ALLOW_PRIVATE_TLS_SCAN = prevAllowPrivate;
      vi.restoreAllMocks();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await fs.rm(tmpDir, { recursive: true, force: true });
    });

    it('blocks private IP resolution when ALLOW_PRIVATE_TLS_SCAN is false', async () => {
      process.env.ALLOW_PRIVATE_TLS_SCAN = 'false';
      const spy = vi.spyOn(dns, 'lookup').mockResolvedValue([
        { address: '127.0.0.1', family: 4 },
      ] as never);

      await expect(performLiveTlsScan('internal.example.com', serverPort)).rejects.toThrow(
        /SSRF policy/i
      );
      spy.mockRestore();
    });

    it('inspects live TLS 1.3 handshake, X.509 certificate metadata, and PQC posture on real TLS server', async () => {
      process.env.ALLOW_PRIVATE_TLS_SCAN = 'true';
      const spy = vi.spyOn(dns, 'lookup').mockResolvedValue([
        { address: '127.0.0.1', family: 4 },
      ] as never);

      const result = await performLiveTlsScan('tls-unit-test.example.com', serverPort);
      spy.mockRestore();

      expect(result.host).toBe('tls-unit-test.example.com');
      expect(result.port).toBe(serverPort);
      expect(result.ip).toBe('127.0.0.1');
      expect(result.tlsVersion).toBe('TLSv1.3');
      expect(result.cipherSuite).toMatch(/TLS_AES_/);
      expect(result.certificate).not.toBeNull();
      expect(result.certificate?.subject).toContain('CN=tls-unit-test.example.com');
      expect(result.certificate?.publicKeyType).toBe('EC');
      expect(result.certificate?.publicKeyBits).toBe(256);
      expect(result.certificate?.daysRemaining).toBeGreaterThan(20);
      expect(result.certificate?.fingerprint256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
      expect(['A+', 'A', 'B', 'C', 'F']).toContain(result.quantumSafeGrade);
      expect(result.quantumSafetyScore).toBeGreaterThanOrEqual(40);
      expect(result.recommendations.length).toBeGreaterThanOrEqual(1);
    });
  });
});
