import { describe, it, expect } from 'vitest';
import { isPrivateOrReservedIp, validateScanTarget } from '../server/app.ts';
import { evaluateTlsPosture } from '../src/engine/moscaRisk.ts';

describe('TLS Scanner Validation, SSRF Guard & NIST Posture Scoring', () => {
  describe('validateScanTarget', () => {
    it('accepts valid public FQDNs and defaults port to 443', () => {
      expect(validateScanTarget('nist.gov', undefined)).toEqual({ host: 'nist.gov', port: 443 });
      expect(validateScanTarget('PQ.CloudflareResearch.com', 8443)).toEqual({
        host: 'pq.cloudflareresearch.com',
        port: 8443,
      });
    });

    it('strips URL schemes and paths before validating FQDN', () => {
      expect(validateScanTarget('https://github.com/org/repo', 443)).toEqual({
        host: 'github.com',
        port: 443,
      });
    });

    it('rejects single-label hosts, IPs, command-injection attempts, and invalid ports', () => {
      expect(() => validateScanTarget('localhost', 443)).toThrow(/Invalid hostname/);
      expect(() => validateScanTarget('127.0.0.1', 443)).toThrow(/Invalid hostname/);
      expect(() => validateScanTarget('nist.gov; whoami', 443)).toThrow(/Invalid hostname/);
      expect(() => validateScanTarget(12345, 443)).toThrow(/valid domain name/);
      expect(() => validateScanTarget('nist.gov', 0)).toThrow(/between 1 and 65535/);
      expect(() => validateScanTarget('nist.gov', 70000)).toThrow(/between 1 and 65535/);
      expect(() => validateScanTarget('nist.gov', 443.5)).toThrow(/between 1 and 65535/);
    });
  });

  describe('isPrivateOrReservedIp (SSRF Prevention)', () => {
    it('blocks IPv4 loopback, RFC 1918 private, link-local metadata, CGNAT, and multicast ranges', () => {
      const blockedIpv4 = [
        '127.0.0.1',
        '127.255.255.254',
        '10.0.0.1',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.1.1',
        '169.254.169.254',
        '100.64.0.1',
        '0.0.0.0',
        '224.0.0.1',
      ];
      for (const ip of blockedIpv4) {
        expect(isPrivateOrReservedIp(ip)).toBe(true);
      }
    });

    it('blocks IPv6 loopback, unspecified, link-local, ULA, and IPv4-mapped private addresses', () => {
      const blockedIpv6 = [
        '::1',
        '::',
        'fe80::1',
        'fc00::1',
        'fd12:3456::1',
        '::ffff:127.0.0.1',
        '::ffff:169.254.169.254',
        '::ffff:10.1.2.3',
      ];
      for (const ip of blockedIpv6) {
        expect(isPrivateOrReservedIp(ip)).toBe(true);
      }
    });

    it('permits valid public IPv4 and IPv6 addresses', () => {
      expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false);
      expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);
      expect(isPrivateOrReservedIp('172.32.0.1')).toBe(false);
      expect(isPrivateOrReservedIp('2606:4700:4700::1111')).toBe(false);
    });
  });

  describe('evaluateTlsPosture NIST & CNSA 2.0 Compliance Edge Cases', () => {
    it('scores TLS 1.3 + ML-KEM-1024 + SLH-DSA-SHA2-256f at 100/100 (Grade A+)', () => {
      const res = evaluateTlsPosture({
        tlsVersion: 'TLSv1.3',
        keyExchange: 'ML-KEM-1024',
        signatureAlgorithm: 'SLH-DSA-SHA2-256f',
        publicKeyType: 'SLH-DSA',
        publicKeyBits: 256,
      });
      expect(res.quantumSafeGrade).toBe('A+');
      expect(res.quantumSafetyScore).toBe(100);
      expect(res.isHybridPQC).toBe(true);
    });

    it('scores TLS 1.3 + classical X25519 + RSA-4096 at 53/100 (Grade C)', () => {
      const res = evaluateTlsPosture({
        tlsVersion: 'TLSv1.3',
        keyExchange: 'X25519',
        signatureAlgorithm: 'RSA-4096 with SHA-256',
        publicKeyType: 'RSA',
        publicKeyBits: 4096,
      });
      expect(res.quantumSafeGrade).toBe('C');
      expect(res.quantumSafetyScore).toBe(53);
      expect(res.isHybridPQC).toBe(false);
      expect(res.recommendations.some((r) => r.includes('RSA-4096'))).toBe(true);
    });

    it('scores TLS 1.3 + X25519 + Ed25519 at 58/100 (Grade C)', () => {
      const res = evaluateTlsPosture({
        tlsVersion: 'TLSv1.3',
        keyExchange: 'X25519',
        signatureAlgorithm: 'Ed25519',
        publicKeyType: 'ED25519',
        publicKeyBits: 256,
      });
      expect(res.quantumSafeGrade).toBe('C');
      expect(res.quantumSafetyScore).toBe(58);
      expect(res.recommendations.some((r) => r.includes('ML-DSA'))).toBe(true);
    });

    it('flags deprecated TLSv1.1 and static key exchange with Grade F', () => {
      const res = evaluateTlsPosture({
        tlsVersion: 'TLSv1.1',
        keyExchange: 'Static RSA',
        signatureAlgorithm: 'RSA with SHA256',
        publicKeyType: 'RSA',
        publicKeyBits: 2048,
      });
      expect(res.quantumSafeGrade).toBe('F');
      expect(res.quantumSafetyScore).toBe(10);
      expect(res.recommendations.some((r) => r.includes('Prohibited legacy protocol'))).toBe(true);
      expect(res.recommendations.some((r) => r.includes('lacks post-quantum forward secrecy'))).toBe(true);
    });
  });
});
