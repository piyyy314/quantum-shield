import express, { type Request, type Response } from 'express';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type {
  AuditSummary,
  CBOMEntry,
  CryptoAsset,
  PolicyFinding,
  PrimitiveCategory,
  RuntimeEnvironmentInfo,
  TLSCertificateInfo,
  TLSScanResult,
} from '../src/types/quantum.ts';
import { classifyPrimitiveRisk, evaluateTlsPosture } from '../src/engine/moscaRisk.ts';
import { scanPolicyContent } from '../src/engine/policyScanner.ts';
import { parsePackageJsonManifest, parseTextManifest } from '../src/engine/cbomBuilder.ts';

const execFileAsync = promisify(execFile);

const HOSTNAME_REGEX = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

export function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(lower.slice(7));
    }
    return false;
  }

  return true;
}

export function validateScanTarget(host: unknown, port: unknown): { host: string; port: number } {
  if (typeof host !== 'string') {
    throw new Error('Target host must be a valid domain name string.');
  }
  const cleanHost = host.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (!HOSTNAME_REGEX.test(cleanHost)) {
    throw new Error('Invalid hostname format. Provide a valid public FQDN (e.g., nist.gov or cloudflare.com).');
  }

  const parsedPort = port === undefined ? 443 : Number(port);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error('Port must be an integer between 1 and 65535.');
  }

  return { host: cleanHost, port: parsedPort };
}

function getRuntimeEnvironmentInfo(): RuntimeEnvironmentInfo {
  const ciphers = crypto.getCiphers();
  const tls13Supported = tls.DEFAULT_MAX_VERSION === 'TLSv1.3' || tls.getCiphers().some((c) => c.includes('aes_256_gcm'));
  const fipsMode = typeof crypto.getFips === 'function' ? crypto.getFips() === 1 : false;

  return {
    nodeVersion: process.version,
    opensslVersion: process.versions.openssl || 'unknown',
    cipherCount: ciphers.length,
    tls13Supported,
    fipsMode,
    platform: `${process.platform} (${process.arch})`,
    timestamp: new Date().toISOString(),
  };
}

async function probeOpenSslBrief(ip: string, host: string, port: number): Promise<{
  kexGroup?: string;
  signatureType?: string;
  hashUsed?: string;
}> {
  try {
    const target = net.isIPv6(ip) ? `[${ip}]:${port}` : `${ip}:${port}`;
    const { stdout, stderr } = await execFileAsync(
      'openssl',
      ['s_client', '-connect', target, '-servername', host, '-brief'],
      { timeout: 4000 }
    ).catch((err: { stdout?: string; stderr?: string }) => ({
      stdout: err.stdout || '',
      stderr: err.stderr || '',
    }));

    const combined = `${stdout}\n${stderr}`;
    const tempKeyMatch = /Server Temp Key:\s*(.+)/i.exec(combined);
    const sigMatch = /Signature type:\s*(.+)/i.exec(combined);
    const hashMatch = /Hash used:\s*(.+)/i.exec(combined);

    return {
      kexGroup: tempKeyMatch?.[1]?.trim(),
      signatureType: sigMatch?.[1]?.trim(),
      hashUsed: hashMatch?.[1]?.trim(),
    };
  } catch {
    return {};
  }
}

async function probeHybridMlKem(ip: string, host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: ip,
        port,
        servername: host,
        ecdhCurve: 'X25519MLKEM768',
        rejectUnauthorized: false,
        timeout: 3500,
      },
      () => {
        socket.end();
        resolve(true);
      }
    );
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      resolve(false);
    });
  });
}

async function performLiveTlsScan(host: string, port: number): Promise<TLSScanResult> {
  const startedAt = Date.now();
  const resolved = await dns.lookup(host, { all: true });
  if (!resolved.length) {
    throw new Error(`DNS resolution returned no addresses for ${host}.`);
  }

  const allowPrivate = process.env.ALLOW_PRIVATE_TLS_SCAN === 'true';
  const publicRecord = resolved.find((r) => !isPrivateOrReservedIp(r.address));
  if (!publicRecord && !allowPrivate) {
    throw new Error(`Target ${host} resolved to a private or reserved IP address, which is blocked by SSRF policy.`);
  }
  const targetIp = (publicRecord ?? resolved[0]).address;

  const tlsData = await new Promise<{
    protocol: string;
    cipherName: string;
    ephemeralKex: string;
    cert: TLSCertificateInfo | null;
    sigAlgHint: string;
  }>((resolve, reject) => {
    const socket = tls.connect(
      {
        host: targetIp,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 5000,
      },
      () => {
        try {
          const protocol = socket.getProtocol() || 'Unknown';
          const cipher = socket.getCipher();
          const cipherName = cipher?.standardName || cipher?.name || 'Unknown';
          const eph = socket.getEphemeralKeyInfo();
          const ephString =
            eph && 'type' in eph && eph.type
              ? `${eph.type}${'name' in eph && eph.name ? ` (${eph.name})` : ''}${'size' in eph && eph.size ? ` ${eph.size}-bit` : ''}`
              : '';

          const x509 = socket.getPeerX509Certificate();
          let certInfo: TLSCertificateInfo | null = null;
          let sigAlgHint = 'Unknown';

          if (x509) {
            const keyType = x509.publicKey.asymmetricKeyType || 'unknown';
            const keyDetails = x509.publicKey.asymmetricKeyDetails || {};
            const keyBits =
              keyDetails.modulusLength ??
              (keyDetails.namedCurve === 'prime256v1' ? 256 : keyDetails.namedCurve === 'secp384r1' ? 384 : null);

            const validToMs = Date.parse(x509.validTo);
            const daysRemaining = Number.isNaN(validToMs)
              ? 0
              : Math.ceil((validToMs - Date.now()) / (1000 * 60 * 60 * 24));

            const sanRaw = x509.subjectAltName || '';
            const subjectAltNames = sanRaw
              .split(',')
              .map((s) => s.trim().replace(/^DNS:/, ''))
              .filter(Boolean)
              .slice(0, 12);

            sigAlgHint = keyType === 'ec' ? `ECDSA (${keyDetails.namedCurve || 'P-256'})` : keyType.toUpperCase();

            certInfo = {
              subject: x509.subject.replace(/\n/g, ', '),
              issuer: x509.issuer.replace(/\n/g, ', '),
              serialNumber: x509.serialNumber,
              validFrom: x509.validFrom,
              validTo: x509.validTo,
              daysRemaining,
              publicKeyType: keyType.toUpperCase(),
              publicKeyBits: keyBits,
              fingerprint256: x509.fingerprint256,
              subjectAltNames,
            };
          }

          socket.end();
          resolve({
            protocol,
            cipherName,
            ephemeralKex: ephString,
            cert: certInfo,
            sigAlgHint,
          });
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`TLS handshake timed out after 5000ms connecting to ${host}:${port}.`));
    });
    socket.on('error', (err) => {
      reject(new Error(`TLS connection failed for ${host}:${port}: ${err.message}`));
    });
  });

  const [openSslMeta, supportsMlKemHybrid] = await Promise.all([
    probeOpenSslBrief(targetIp, host, port),
    tlsData.protocol === 'TLSv1.3' ? probeHybridMlKem(targetIp, host, port) : Promise.resolve(false),
  ]);
  const latencyMs = Date.now() - startedAt;

  const keyExchange = supportsMlKemHybrid
    ? 'X25519MLKEM768 (FIPS 203 Hybrid)'
    : openSslMeta.kexGroup || tlsData.ephemeralKex || `${tlsData.cipherName} Ephemeral`;
  const signatureAlgorithm = openSslMeta.signatureType
    ? `${openSslMeta.signatureType}${openSslMeta.hashUsed ? ` with ${openSslMeta.hashUsed}` : ''}`
    : tlsData.sigAlgHint;

  const posture = evaluateTlsPosture({
    tlsVersion: tlsData.protocol,
    keyExchange,
    signatureAlgorithm,
    publicKeyType: tlsData.cert?.publicKeyType,
    publicKeyBits: tlsData.cert?.publicKeyBits,
  });

  return {
    host,
    port,
    ip: targetIp,
    tlsVersion: tlsData.protocol,
    cipherSuite: tlsData.cipherName,
    keyExchange,
    signatureAlgorithm,
    quantumSafeGrade: posture.quantumSafeGrade,
    quantumSafetyScore: posture.quantumSafetyScore,
    isHybridPQC: posture.isHybridPQC,
    latencyMs,
    scannedAt: new Date().toISOString(),
    certificate: tlsData.cert,
    recommendations: posture.recommendations,
  };
}

async function collectWorkspaceFiles(dir: string, rootDir: string, acc: string[] = []): Promise<string[]> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (
        entry.name === 'node_modules' ||
        entry.name === 'dist' ||
        entry.name === '.git' ||
        entry.name === 'tests'
      ) {
        continue;
      }
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const relDir = path.relative(rootDir, fullPath).replace(/\\/g, '/');
        if (relDir === 'src/data' || relDir === 'src/engine' || relDir === 'src/components') {
          continue;
        }
        await collectWorkspaceFiles(fullPath, rootDir, acc);
      } else if (/\.(ts|tsx|js|jsx|json|env\.example)$/i.test(entry.name)) {
        const rel = path.relative(rootDir, fullPath).replace(/\\/g, '/');
        if (rel !== 'package-lock.json') {
          acc.push(fullPath);
        }
      }
    }
  } catch {
    // Ignore unreadable directories
  }
  return acc;
}

async function buildLiveWorkspaceInventory(rootDir: string): Promise<{
  assets: CryptoAsset[];
  cbomEntries: CBOMEntry[];
  workspaceFilesScanned: number;
  workspaceFindings: PolicyFinding[];
  runtime: RuntimeEnvironmentInfo;
}> {
  const now = new Date().toISOString();
  const runtime = getRuntimeEnvironmentInfo();
  const assets: CryptoAsset[] = [];

  // 1. Read real package.json to discover cryptographic dependencies
  let cbomEntries: CBOMEntry[] = [];
  try {
    const pkgRaw = await fs.readFile(path.join(rootDir, 'package.json'), 'utf8');
    cbomEntries = parsePackageJsonManifest(pkgRaw, 'package.json');
  } catch {
    cbomEntries = [];
  }

  // 2. Register real active runtime primitives discovered in this Node.js + @noble/post-quantum environment
  const hasNoblePqc = cbomEntries.some((c) => c.component === '@noble/post-quantum');
  if (hasNoblePqc) {
    assets.push({
      id: 'runtime-pqc-kem',
      name: 'Post-Quantum Key Encapsulation Engine (@noble/post-quantum)',
      system: 'Application Cryptographic Engine',
      algorithm: 'ML-KEM-768 / ML-KEM-1024 + X25519 Hybrid',
      keySize: 768,
      primitiveType: 'PQC Native',
      quantumRisk: 'COMPLIANT',
      shelfLifeYears: 20,
      migrationTimeMonths: 0,
      recommendedPQC: 'NIST FIPS 203 (Active)',
      notes: 'Live pure-TypeScript FIPS 203 ML-KEM and X25519+ML-KEM-768 hybrid implementation backed by Web Crypto CSPRNG.',
      source: 'workspace',
      discoveredAt: now,
    });

    assets.push({
      id: 'runtime-pqc-dsa',
      name: 'Post-Quantum Signature Engine (@noble/post-quantum)',
      system: 'Application Cryptographic Engine',
      algorithm: 'ML-DSA-65 / ML-DSA-87 / SLH-DSA',
      keySize: 1952,
      primitiveType: 'PQC Native',
      quantumRisk: 'COMPLIANT',
      shelfLifeYears: 20,
      migrationTimeMonths: 0,
      recommendedPQC: 'NIST FIPS 204 & 205 (Active)',
      notes: 'Live FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) signing and verification primitives.',
      source: 'workspace',
      discoveredAt: now,
    });
  }

  // 3. Real OpenSSL / Node.js runtime cryptographic engine inspection
  const opensslMajMin = runtime.opensslVersion.split('.').slice(0, 2).join('.');
  const opensslMajor = Number(runtime.opensslVersion.split('.')[0]) || 3;
  const opensslMinor = Number(runtime.opensslVersion.split('.')[1]) || 0;
  const opensslSupportsNativeMlKem = opensslMajor > 3 || (opensslMajor === 3 && opensslMinor >= 5);

  assets.push({
    id: 'runtime-openssl-tls',
    name: `Host TLS Transport Stack (OpenSSL ${runtime.opensslVersion})`,
    system: `Node.js ${runtime.nodeVersion} (${runtime.platform})`,
    algorithm: opensslSupportsNativeMlKem ? 'TLS 1.3 + X25519MLKEM768' : 'TLS 1.3 (X25519 / ECDHE-P256)',
    keySize: 256,
    primitiveType: opensslSupportsNativeMlKem ? 'PQC Hybrid' : 'Asymmetric',
    quantumRisk: opensslSupportsNativeMlKem ? 'COMPLIANT' : 'HIGH',
    shelfLifeYears: 5,
    migrationTimeMonths: opensslSupportsNativeMlKem ? 0 : 6,
    recommendedPQC: 'OpenSSL 3.5+ ML-KEM Provider or Reverse Proxy Hybrid TLS',
    notes: opensslSupportsNativeMlKem
      ? `OpenSSL ${opensslMajMin} natively supports FIPS 203 ML-KEM hybrid groups.`
      : `Detected OpenSSL ${runtime.opensslVersion} (${runtime.cipherCount} ciphers). Classical ECDHE/X25519 TLS handshakes require OpenSSL 3.5+ or an edge PQC TLS terminator.`,
    source: 'runtime',
    discoveredAt: now,
  });

  assets.push({
    id: 'runtime-webcrypto-hash',
    name: 'Key Fingerprint & Symmetric Primitive Engine (Web Crypto)',
    system: `Node.js ${runtime.nodeVersion} WebCrypto / OpenSSL`,
    algorithm: 'SHA-256 / AES-256-GCM',
    keySize: 256,
    primitiveType: 'Symmetric',
    quantumRisk: 'COMPLIANT',
    shelfLifeYears: 15,
    migrationTimeMonths: 0,
    recommendedPQC: 'AES-256-GCM / SHA-384 (Grover-Resilient)',
    notes: 'Used for live cryptographic key fingerprinting and symmetric integrity verification.',
    source: 'runtime',
    discoveredAt: now,
  });

  // 4. Scan real workspace files for cryptographic policy issues
  const files = await collectWorkspaceFiles(rootDir, rootDir);
  const workspaceFindings: PolicyFinding[] = [];
  for (const filePath of files) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const rel = path.relative(rootDir, filePath).replace(/\\/g, '/');
      const found = scanPolicyContent(content, rel);
      workspaceFindings.push(...found);
    } catch {
      // Skip binary/unreadable
    }
  }

  return {
    assets,
    cbomEntries,
    workspaceFilesScanned: files.length,
    workspaceFindings,
    runtime,
  };
}

export function createApp(options?: { rootDir?: string }) {
  const rootDir = options?.rootDir ?? process.cwd();
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Live in-memory extension store for user-added assets & live TLS scan imports
  const customAssets: CryptoAsset[] = [];

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'quantumshield-suite',
      runtime: getRuntimeEnvironmentInfo(),
    });
  });

  app.get('/api/inventory', async (_req: Request, res: Response) => {
    try {
      const live = await buildLiveWorkspaceInventory(rootDir);
      res.json({
        assets: [...customAssets, ...live.assets],
        runtime: live.runtime,
        cbomCount: live.cbomEntries.length,
        workspaceFilesScanned: live.workspaceFilesScanned,
      });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to inspect workspace inventory.' });
    }
  });

  app.post('/api/inventory', (req: Request, res: Response) => {
    const { name, system, algorithm, keySize, primitiveType, shelfLifeYears, migrationTimeMonths, notes } = req.body ?? {};
    if (!name || typeof name !== 'string' || !algorithm || typeof algorithm !== 'string') {
      res.status(400).json({ error: 'Asset name and algorithm are required.' });
      return;
    }

    const validPrimitives: PrimitiveCategory[] = ['Asymmetric', 'Symmetric', 'Hash', 'PQC Hybrid', 'PQC Native'];
    const pType: PrimitiveCategory = validPrimitives.includes(primitiveType) ? primitiveType : 'Asymmetric';
    const numericKeySize = Number(keySize) > 0 ? Number(keySize) : 256;
    const evaluation = classifyPrimitiveRisk(algorithm, numericKeySize, pType);

    const newAsset: CryptoAsset = {
      id: `ast-${crypto.randomUUID().slice(0, 8)}`,
      name: name.trim(),
      system: typeof system === 'string' && system.trim() ? system.trim() : 'Custom System',
      algorithm: algorithm.trim(),
      keySize: numericKeySize,
      primitiveType: pType,
      quantumRisk: evaluation.risk,
      shelfLifeYears: Math.max(1, Number(shelfLifeYears) || 5),
      migrationTimeMonths: Math.max(0, Number(migrationTimeMonths) || 6),
      recommendedPQC: evaluation.recommendedPQC,
      notes: typeof notes === 'string' && notes.trim() ? notes.trim() : 'Added via live cryptographic inventory.',
      source: 'manual',
      discoveredAt: new Date().toISOString(),
    };

    customAssets.unshift(newAsset);
    res.status(201).json(newAsset);
  });

  app.delete('/api/inventory/:id', (req: Request, res: Response) => {
    const idx = customAssets.findIndex((a) => a.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'Custom asset not found or is a live runtime baseline asset.' });
      return;
    }
    const [removed] = customAssets.splice(idx, 1);
    res.json({ deleted: removed.id });
  });

  app.post('/api/tls-scan', async (req: Request, res: Response) => {
    try {
      const { host, port } = validateScanTarget(req.body?.host, req.body?.port);
      const result = await performLiveTlsScan(host, port);

      if (req.body?.recordInInventory) {
        const keyBits = result.certificate?.publicKeyBits ?? 256;
        const asset: CryptoAsset = {
          id: `tls-${host}-${port}`,
          name: `Live TLS Endpoint (${host}:${port})`,
          system: `IP ${result.ip} · ${result.tlsVersion}`,
          algorithm: `${result.keyExchange} / ${result.signatureAlgorithm}`,
          keySize: keyBits,
          primitiveType: result.isHybridPQC ? 'PQC Hybrid' : 'Asymmetric',
          quantumRisk:
            result.quantumSafeGrade === 'A+' || result.quantumSafeGrade === 'A'
              ? 'COMPLIANT'
              : result.quantumSafeGrade === 'B'
              ? 'MEDIUM'
              : 'CRITICAL',
          shelfLifeYears: 5,
          migrationTimeMonths: result.isHybridPQC ? 0 : 12,
          recommendedPQC: result.isHybridPQC
            ? 'Verify ML-DSA certificate chain migration'
            : 'Enable X25519MLKEM768 hybrid key exchange',
          notes: `Live TLS scan grade ${result.quantumSafeGrade} (${result.quantumSafetyScore}/100) via ${result.cipherSuite}.`,
          source: 'tls-scan',
          discoveredAt: result.scannedAt,
        };

        const existingIdx = customAssets.findIndex((a) => a.id === asset.id);
        if (existingIdx >= 0) {
          customAssets[existingIdx] = asset;
        } else {
          customAssets.unshift(asset);
        }
      }

      res.json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'TLS scan failed.';
      const status =
        message.includes('Invalid hostname') ||
        message.includes('Port must be') ||
        message.includes('Target host must') ||
        message.includes('SSRF policy')
          ? 400
          : 502;
      res.status(status).json({ error: message });
    }
  });

  app.get('/api/cbom', async (_req: Request, res: Response) => {
    try {
      const pkgRaw = await fs.readFile(path.join(rootDir, 'package.json'), 'utf8');
      const entries = parsePackageJsonManifest(pkgRaw, 'package.json');
      res.json({
        manifest: 'package.json',
        generatedAt: new Date().toISOString(),
        entries,
      });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to build CBOM.' });
    }
  });

  app.post('/api/cbom/parse', (req: Request, res: Response) => {
    const { manifestType, content } = req.body ?? {};
    if (typeof content !== 'string' || !content.trim()) {
      res.status(400).json({ error: 'Manifest file content is required.' });
      return;
    }

    try {
      let entries: CBOMEntry[] = [];
      if (manifestType === 'package.json') {
        entries = parsePackageJsonManifest(content, 'uploaded package.json');
      } else if (
        manifestType === 'requirements.txt' ||
        manifestType === 'go.mod' ||
        manifestType === 'Cargo.toml'
      ) {
        entries = parseTextManifest(content, manifestType);
      } else {
        res.status(400).json({ error: 'Unsupported manifestType. Use package.json, requirements.txt, go.mod, or Cargo.toml.' });
        return;
      }

      res.json({
        manifest: manifestType,
        generatedAt: new Date().toISOString(),
        entries,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? `Failed to parse manifest: ${err.message}` : 'Invalid manifest format.' });
    }
  });

  app.post('/api/policy-scan', (req: Request, res: Response) => {
    const { content, fileName } = req.body ?? {};
    if (typeof content !== 'string') {
      res.status(400).json({ error: 'Code or configuration content string is required.' });
      return;
    }
    const findings = scanPolicyContent(content, typeof fileName === 'string' ? fileName : undefined);
    res.json({
      scannedAt: new Date().toISOString(),
      linesScanned: content.split(/\r?\n/).length,
      findings,
    });
  });

  app.post('/api/audit', async (_req: Request, res: Response) => {
    try {
      const live = await buildLiveWorkspaceInventory(rootDir);
      const allAssets = [...customAssets, ...live.assets];
      const summary: AuditSummary = {
        auditId: crypto.randomUUID(),
        auditedAt: new Date().toISOString(),
        runtime: live.runtime,
        assetsDiscovered: allAssets.length,
        cbomComponentsCount: live.cbomEntries.length,
        workspaceFilesScanned: live.workspaceFilesScanned,
        workspaceFindings: live.workspaceFindings,
        assets: allAssets,
        cbomEntries: live.cbomEntries,
      };
      res.json(summary);
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Workspace audit failed.' });
    }
  });

  return app;
}
