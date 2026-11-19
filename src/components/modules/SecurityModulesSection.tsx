import React, { useState } from 'react';
import { 
  KeyRound, 
  Radio, 
  Layers, 
  FileCode2, 
  Copy, 
  Check, 
  Download, 
  Play, 
  RotateCw, 
  ShieldCheck, 
  AlertTriangle,
  FileDown,
  Terminal,
  Search
} from 'lucide-react';
import { SecuritySubModule, CBOMEntry, TLSScanResult, RiskLevel } from '../../types/quantum';
import { INITIAL_CBOM_ENTRIES, SAMPLE_TLS_HOSTS } from '../../data/mockQuantumData';

interface SecurityModulesSectionProps {
  activeSubModule: SecuritySubModule;
  onSelectSubModule: (module: SecuritySubModule) => void;
}

export const SecurityModulesSection: React.FC<SecurityModulesSectionProps> = ({
  activeSubModule,
  onSelectSubModule,
}) => {
  // PQC Key Generator State
  const [selectedAlgo, setSelectedAlgo] = useState<'ml-kem-768' | 'ml-kem-1024' | 'ml-dsa-65' | 'ml-dsa-87' | 'falcon-512' | 'slh-dsa'>('ml-kem-768');
  const [generatedKey, setGeneratedKey] = useState<{
    algorithm: string;
    nistLevel: number;
    publicKeyPem: string;
    privateKeyPem: string;
    fingerprint: string;
    publicKeyBytes: number;
    estimatedLifetime: string;
  } | null>(null);
  const [isGeneratingKey, setIsGeneratingKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);

  // TLS Scanner State
  const [targetHost, setTargetHost] = useState<string>('api.production.internal');
  const [isScanningHost, setIsScanningHost] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<TLSScanResult | null>(SAMPLE_TLS_HOSTS[0]);

  // CBOM State
  const [cbomEntries, setCbomEntries] = useState<CBOMEntry[]>(INITIAL_CBOM_ENTRIES);
  const [cbomFilter, setCbomFilter] = useState<string>('ALL');

  // Policy Scanner State
  const [sampleCode, setSampleCode] = useState<string>(
`# Enterprise Service Configuration
TLS_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
SIGNING_KEY_PATH = "/etc/ssl/certs/rsa2048_private.pem"
HASH_ALGORITHM = "MD5"  # Deprecated legacy hash
STORAGE_ENCRYPTION = "AES-128-CBC"
SESSION_KEY_EXCHANGE = "diffie-hellman-group14-sha1"
PQC_HYBRID_ENABLED = false`
  );
  const [policyFindings, setPolicyFindings] = useState<{ line: number; rule: string; severity: RiskLevel; fix: string }[]>([]);
  const [hasScannedPolicy, setHasScannedPolicy] = useState<boolean>(false);

  // Helper to generate simulated PQC key
  const handleGenerateKey = () => {
    setIsGeneratingKey(true);
    setTimeout(() => {
      let algoName = 'ML-KEM-768 (CRYSTALS-Kyber)';
      let nistLevel = 3;
      let pkBytes = 1184;
      let lifetime = '2035+ (Post-Quantum Resilient)';

      if (selectedAlgo === 'ml-kem-1024') {
        algoName = 'ML-KEM-1024 (CRYSTALS-Kyber)';
        nistLevel = 5;
        pkBytes = 1568;
      } else if (selectedAlgo === 'ml-dsa-65') {
        algoName = 'ML-DSA-65 (CRYSTALS-Dilithium)';
        nistLevel = 3;
        pkBytes = 1952;
      } else if (selectedAlgo === 'ml-dsa-87') {
        algoName = 'ML-DSA-87 (CRYSTALS-Dilithium)';
        nistLevel = 5;
        pkBytes = 2592;
      } else if (selectedAlgo === 'falcon-512') {
        algoName = 'Falcon-512';
        nistLevel = 1;
        pkBytes = 897;
      } else if (selectedAlgo === 'slh-dsa') {
        algoName = 'SLH-DSA-SHA2-128f (SPHINCS+)';
        nistLevel = 1;
        pkBytes = 32;
      }

      // Generate random-looking deterministic hex bytes
      const randomHex = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const fingerprint = `SHA256:${randomHex.slice(0, 8)}:${randomHex.slice(8, 16)}:${randomHex.slice(16, 24)}:${randomHex.slice(24, 32)}`;

      const dummyBase64 = btoa(`PQC_M_LWE_SIMULATED_KEY_CONTAINER_${algoName}_${Date.now()}_FIPS_COMPLIANT_${randomHex}`);
      
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----
${dummyBase64.match(/.{1,64}/g)?.join('\n') || dummyBase64}
-----END PUBLIC KEY-----`;

      const privateKeyPem = `-----BEGIN PRIVATE KEY-----
${btoa(`PQC_SECRET_PARAM_${randomHex}`).match(/.{1,64}/g)?.join('\n')}
-----END PRIVATE KEY-----`;

      setGeneratedKey({
        algorithm: algoName,
        nistLevel,
        publicKeyPem,
        privateKeyPem,
        fingerprint,
        publicKeyBytes: pkBytes,
        estimatedLifetime: lifetime,
      });
      setIsGeneratingKey(false);
    }, 450);
  };

  const handleCopyKey = () => {
    if (!generatedKey) return;
    navigator.clipboard.writeText(generatedKey.publicKeyPem);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleDownloadKey = () => {
    if (!generatedKey) return;
    const blob = new Blob([generatedKey.publicKeyPem], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedAlgo}_public_key.pem`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Helper to trigger TLS scan
  const handleRunTlsScan = () => {
    setIsScanningHost(true);
    setTimeout(() => {
      const match = SAMPLE_TLS_HOSTS.find((h) => h.host.toLowerCase().includes(targetHost.toLowerCase()));
      if (match) {
        setScanResult(match);
      } else {
        // Dynamic scan generation
        setScanResult({
          host: targetHost,
          port: 443,
          ip: '198.51.100.44',
          tlsVersion: 'TLSv1.3',
          keyExchange: 'X25519 (Classical - Vulnerable to SNDL)',
          signatureAlgorithm: 'RSA-2048 with SHA-256',
          quantumSafeGrade: 'C',
          quantumSafetyScore: 45,
          isHybridPQC: false,
          recommendations: [
            'Enable hybrid post-quantum key exchange (X25519+ML-KEM-768)',
            'Deprecated RSA-2048 server certificate should be upgraded to ML-DSA-65 or hybrid ECDSA/Dilithium',
            'Ensure HSTS and TLS 1.3 are strictly enforced',
          ],
        });
      }
      setIsScanningHost(false);
    }, 700);
  };

  // Export CBOM to CycloneDX JSON
  const handleExportCycloneDX = () => {
    const cycloneDxReport = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:pqc-cbom-${Date.now()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          type: 'application',
          name: 'Enterprise Cryptographic Inventory',
          version: '2.4.0',
        },
      },
      components: cbomEntries.map((c) => ({
        name: c.component,
        version: c.version,
        purl: `pkg:generic/${c.component}@${c.version}`,
        cryptoProperties: {
          assetType: 'algorithm',
          algorithm: c.algorithm,
          nistStatus: c.nistStandard,
          quantumRisk: c.riskLevel,
        },
      })),
    };

    const blob = new Blob([JSON.stringify(cycloneDxReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `crypto_sbom_cyclonedx_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Helper for Policy Scanner
  const handleRunPolicyScan = () => {
    const findings: { line: number; rule: string; severity: RiskLevel; fix: string }[] = [];
    const lines = sampleCode.split('\n');

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const lower = lineText.toLowerCase();

      if (lower.includes('md5')) {
        findings.push({
          line: lineNum,
          rule: 'Prohibited Legacy Hash (MD5)',
          severity: 'CRITICAL',
          fix: 'Replace MD5 with SHA-384 or SHA-512 for CNSA 2.0 compliance.',
        });
      }
      if (lower.includes('rsa2048') || lower.includes('rsa-2048') || lower.includes('rsa_private')) {
        findings.push({
          line: lineNum,
          rule: 'Quantum Vulnerable Asymmetric Key (RSA-2048)',
          severity: 'CRITICAL',
          fix: 'Migrate to ML-DSA-65 (FIPS 204) for digital signatures.',
        });
      }
      if (lower.includes('aes-128') || lower.includes('aes128')) {
        findings.push({
          line: lineNum,
          rule: 'Grover Borderline Key Size (AES-128)',
          severity: 'MEDIUM',
          fix: 'Upgrade to AES-256-GCM to preserve at least 128-bit post-quantum security margin.',
        });
      }
      if (lower.includes('diffie-hellman') || lower.includes('sha1')) {
        findings.push({
          line: lineNum,
          rule: 'Vulnerable Key Agreement & SHA-1',
          severity: 'CRITICAL',
          fix: 'Adopt ML-KEM-768 hybrid key agreement (IETF draft-ietf-tls-hybrid-design).',
        });
      }
      if (lower.includes('pqc_hybrid_enabled = false')) {
        findings.push({
          line: lineNum,
          rule: 'Post-Quantum Defense Disabled',
          severity: 'HIGH',
          fix: 'Set PQC_HYBRID_ENABLED = true to initiate dual-key post-quantum handshake.',
        });
      }
    });

    setPolicyFindings(findings);
    setHasScannedPolicy(true);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Sub-module Navigation Header */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">
            Operational Security Engines
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Active cryptographic auditing, key generation, and compliance validation toolset.
          </p>
        </div>

        {/* Sub-module switch tabs */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-950 rounded-lg border border-slate-800">
          <button
            onClick={() => onSelectSubModule('key-generator')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 ${
              activeSubModule === 'key-generator'
                ? 'bg-slate-800 text-emerald-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>PQC Key Generator</span>
          </button>

          <button
            onClick={() => onSelectSubModule('tls-scanner')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 ${
              activeSubModule === 'tls-scanner'
                ? 'bg-slate-800 text-cyan-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Quantum TLS Scanner</span>
          </button>

          <button
            onClick={() => onSelectSubModule('cbom')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 ${
              activeSubModule === 'cbom'
                ? 'bg-slate-800 text-purple-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Cryptographic SBOM</span>
          </button>

          <button
            onClick={() => onSelectSubModule('policy-scanner')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 ${
              activeSubModule === 'policy-scanner'
                ? 'bg-slate-800 text-amber-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Policy & Code Scanner</span>
          </button>
        </div>
      </div>

      {/* MODULE 1: PQC Key Generator */}
      {activeSubModule === 'key-generator' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5">
            <div>
              <h2 className="text-base font-bold text-white">Post-Quantum Key Synthesizer</h2>
              <p className="text-xs text-slate-400 mt-1">
                Generate lattice-based (M-LWE) and stateless hash-based keypairs compliant with NIST FIPS 203/204.
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Target Post-Quantum Algorithm
                </label>
                <select
                  value={selectedAlgo}
                  onChange={(e) => setSelectedAlgo(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <option value="ml-kem-768">ML-KEM-768 (CRYSTALS-Kyber) · NIST Level 3</option>
                  <option value="ml-kem-1024">ML-KEM-1024 (CRYSTALS-Kyber) · NIST Level 5</option>
                  <option value="ml-dsa-65">ML-DSA-65 (CRYSTALS-Dilithium) · NIST Level 3</option>
                  <option value="ml-dsa-87">ML-DSA-87 (CRYSTALS-Dilithium) · NIST Level 5</option>
                  <option value="falcon-512">Falcon-512 · Compact Lattice Signature</option>
                  <option value="slh-dsa">SLH-DSA-SHA2-128f (SPHINCS+) · Stateless Hash</option>
                </select>
              </div>

              <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 space-y-1.5 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Standardization:</span>
                  <span className="text-emerald-400 font-mono">FIPS 203 / 204</span>
                </div>
                <div className="flex justify-between">
                  <span>Underlying Math:</span>
                  <span className="text-slate-200 font-mono">Module Learning with Errors</span>
                </div>
                <div className="flex justify-between">
                  <span>Quantum Resistance:</span>
                  <span className="text-emerald-400 font-mono">Shor & Grover Immune</span>
                </div>
              </div>

              <button
                onClick={handleGenerateKey}
                disabled={isGeneratingKey}
                className="w-full py-2.5 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
              >
                <Play className={`w-3.5 h-3.5 ${isGeneratingKey ? 'animate-spin' : ''}`} />
                <span>{isGeneratingKey ? 'Synthesizing Lattice Vectors...' : 'Generate PQC Keypair'}</span>
              </button>
            </div>
          </div>

          <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-white">Generated Public Key & Certificate Material</h2>
                <p className="text-xs text-slate-400">PEM formatted cryptographic container</p>
              </div>

              {generatedKey && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyKey}
                    className="p-1.5 text-slate-300 hover:text-white bg-slate-800 rounded border border-slate-700 text-xs inline-flex items-center gap-1.5 transition-colors"
                    title="Copy Public Key"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={handleDownloadKey}
                    className="p-1.5 text-slate-300 hover:text-white bg-slate-800 rounded border border-slate-700 text-xs inline-flex items-center gap-1.5 transition-colors"
                    title="Download PEM File"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download</span>
                  </button>
                </div>
              )}
            </div>

            {generatedKey ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] block">ALGORITHM</span>
                    <span className="text-slate-200 font-mono font-semibold truncate block">
                      {generatedKey.algorithm}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] block">NIST LEVEL</span>
                    <span className="text-emerald-400 font-mono font-semibold block">
                      Level {generatedKey.nistLevel}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] block">KEY SIZE</span>
                    <span className="text-slate-200 font-mono font-semibold block">
                      {generatedKey.publicKeyBytes} bytes
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] block">LIFETIME</span>
                    <span className="text-emerald-400 font-mono font-semibold block">
                      2035+ Secure
                    </span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <span className="text-xs font-mono text-slate-400">
                    KEY FINGERPRINT: <span className="text-slate-200">{generatedKey.fingerprint}</span>
                  </span>
                  <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto leading-relaxed select-all">
                    {generatedKey.publicKeyPem}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center border border-dashed border-slate-800 rounded-lg space-y-3">
                <KeyRound className="w-8 h-8 text-slate-600 mx-auto" />
                <div className="text-sm font-medium text-slate-300">No Key Generated Yet</div>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Select an algorithm on the left and click "Generate PQC Keypair" to synthesize simulated NIST post-quantum keys.
                </p>
                <button
                  onClick={handleGenerateKey}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 rounded-lg border border-slate-700"
                >
                  Generate Default ML-KEM-768
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODULE 2: Quantum TLS Scanner */}
      {activeSubModule === 'tls-scanner' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <h2 className="text-base font-bold text-white">Quantum TLS / SSL Readiness Audit</h2>
            <p className="text-xs text-slate-400">
              Probe endpoints for post-quantum hybrid key exchange (X25519Kyber768), certificate signature schemes, and forward secrecy.
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Radio className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  placeholder="Enter hostname or IP (e.g. api.internal.corp)"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunTlsScan}
                  disabled={isScanningHost}
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 whitespace-nowrap"
                >
                  <RotateCw className={`w-3.5 h-3.5 ${isScanningHost ? 'animate-spin' : ''}`} />
                  <span>{isScanningHost ? 'Handshaking...' : 'Scan Host'}</span>
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="font-mono text-slate-500">Preset Targets:</span>
              {SAMPLE_TLS_HOSTS.map((sample) => (
                <button
                  key={sample.host}
                  onClick={() => {
                    setTargetHost(sample.host);
                    setScanResult(sample);
                  }}
                  className="text-xs font-mono text-slate-300 hover:text-cyan-400 underline decoration-slate-700"
                >
                  {sample.host}
                </button>
              ))}
            </div>
          </div>

          {/* Results Panel */}
          {scanResult && (
            <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-white font-mono">{scanResult.host}:{scanResult.port}</span>
                    <span className="text-xs text-slate-500 font-mono">({scanResult.ip})</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Protocol: <span className="font-mono text-slate-200">{scanResult.tlsVersion}</span>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">QUANTUM GRADE</span>
                    <span className={`text-2xl font-bold font-mono ${
                      scanResult.quantumSafeGrade.startsWith('A') ? 'text-emerald-400' :
                      scanResult.quantumSafeGrade === 'B' ? 'text-amber-400' : 'text-rose-400'
                    }`}>
                      {scanResult.quantumSafeGrade}
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">SAFETY SCORE</span>
                    <span className="text-2xl font-bold font-mono text-white">
                      {scanResult.quantumSafetyScore}<span className="text-xs text-slate-500">/100</span>
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">Key Exchange Mechanism</span>
                  <div className="text-slate-200 font-semibold">{scanResult.keyExchange}</div>
                  <div className={`text-[11px] ${scanResult.isHybridPQC ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {scanResult.isHybridPQC ? '✓ Quantum resistant against interception' : '✗ Vulnerable to harvest now, decrypt later'}
                  </div>
                </div>

                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">Certificate Signature Scheme</span>
                  <div className="text-slate-200 font-semibold">{scanResult.signatureAlgorithm}</div>
                  <div className="text-[11px] text-slate-400">
                    End-entity and intermediate chain verification
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-xs font-bold text-slate-200 uppercase font-mono">Remediation Steps</h3>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {scanResult.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-emerald-400 font-mono shrink-0">→</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MODULE 3: Cryptographic SBOM (CBOM) */}
      {activeSubModule === 'cbom' && (
        <div className="space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-white">Cryptographic Bill of Materials (CBOM)</h2>
              <p className="text-xs text-slate-400 mt-1">
                Standardized software bill of materials cataloging crypto algorithms, dependencies, and NIST readiness.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleExportCycloneDX}
                className="px-3.5 py-2 bg-purple-500 hover:bg-purple-400 text-white font-semibold text-xs rounded-lg transition-colors inline-flex items-center gap-2"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>Export CycloneDX 1.5 JSON</span>
              </button>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px]">
                    <th className="py-3 px-4 font-medium">LIBRARY COMPONENT</th>
                    <th className="py-3 px-4 font-medium">VERSION</th>
                    <th className="py-3 px-4 font-medium">CRYPTOGRAPHIC PRIMITIVES</th>
                    <th className="py-3 px-4 font-medium">PURPOSE</th>
                    <th className="py-3 px-4 font-medium">RISK LEVEL</th>
                    <th className="py-3 px-4 font-medium">NIST STANDARD</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {cbomEntries.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono font-semibold text-slate-200">
                        {entry.component}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {entry.version}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {entry.algorithm}
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {entry.purpose}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`font-mono text-xs font-semibold ${
                          entry.riskLevel === 'CRITICAL' ? 'text-rose-400' :
                          entry.riskLevel === 'HIGH' ? 'text-amber-400' :
                          entry.riskLevel === 'MEDIUM' ? 'text-yellow-400' : 'text-emerald-400'
                        }`}>
                          [{entry.riskLevel}]
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {entry.nistStandard}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* MODULE 4: Policy & Deprecated Crypto Scanner */}
      {activeSubModule === 'policy-scanner' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Cryptographic Policy & Code Linter</h2>
                <p className="text-xs text-slate-400">Audit configuration files and codebases for deprecated algorithms</p>
              </div>
              <button
                onClick={handleRunPolicyScan}
                className="px-3.5 py-1.5 bg-amber-400 hover:bg-amber-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Audit Code</span>
              </button>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 font-mono">
                CONFIGURATION FILE SNIPPET:
              </label>
              <textarea
                value={sampleCode}
                onChange={(e) => setSampleCode(e.target.value)}
                rows={10}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:ring-1 focus:ring-amber-500 leading-relaxed"
              />
            </div>
          </div>

          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <h2 className="text-sm font-bold text-white border-b border-slate-800 pb-3">
              Policy Compliance Findings ({policyFindings.length})
            </h2>

            {hasScannedPolicy ? (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                {policyFindings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-amber-400 font-semibold">
                        Line {finding.line}: {finding.rule}
                      </span>
                      <span className={`font-mono text-[10px] ${
                        finding.severity === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                      }`}>
                        [{finding.severity}]
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">
                      <strong className="text-slate-300">Remediation:</strong> {finding.fix}
                    </p>
                  </div>
                ))}
                {policyFindings.length === 0 && (
                  <div className="p-8 text-center text-emerald-400 font-mono text-xs">
                    ✓ Clean: No cryptographic policy violations found.
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center text-slate-500 text-xs">
                Click "Audit Code" above to check the configuration for weak ciphers and missing PQC flags.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
