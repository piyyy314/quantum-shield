import React, { useEffect, useState } from 'react';
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
  FileDown,
  ShieldCheck,
  Eye,
  EyeOff,
  Upload,
  AlertCircle,
} from 'lucide-react';
import type {
  CBOMEntry,
  PolicyFinding,
  RiskLevel,
  SecuritySubModule,
  TLSScanResult,
} from '../../types/quantum';
import {
  PQC_ALGORITHM_CATALOG,
  generatePqcKeyPair,
  verifyKemRoundTrip,
  verifySignatureRoundTrip,
  type GeneratedPqcKeyPair,
  type KemRoundTripResult,
  type PqcAlgorithmId,
  type SignatureRoundTripResult,
} from '../../engine/pqcCrypto';
import { buildCycloneDxCbom } from '../../engine/cbomBuilder';

interface SecurityModulesSectionProps {
  activeSubModule: SecuritySubModule;
  onSelectSubModule: (module: SecuritySubModule) => void;
  preselectedAlgorithm?: PqcAlgorithmId;
  cbomEntries: CBOMEntry[];
  onUpdateCbomEntries: (entries: CBOMEntry[]) => void;
  workspaceFindings: PolicyFinding[];
  searchQuery: string;
  onTlsAssetRecorded: () => Promise<void>;
}

const PUBLIC_TLS_PRESETS = ['nist.gov', 'cloudflare.com', 'github.com', 'google.com'];

export const SecurityModulesSection: React.FC<SecurityModulesSectionProps> = ({
  activeSubModule,
  onSelectSubModule,
  preselectedAlgorithm,
  cbomEntries,
  onUpdateCbomEntries,
  workspaceFindings,
  searchQuery,
  onTlsAssetRecorded,
}) => {
  // PQC Key Generator State
  const [selectedAlgo, setSelectedAlgo] = useState<PqcAlgorithmId>(
    preselectedAlgorithm || 'ml-kem-768'
  );
  const [generatedKey, setGeneratedKey] = useState<GeneratedPqcKeyPair | null>(null);
  const [isGeneratingKey, setIsGeneratingKey] = useState<boolean>(false);
  const [showPrivateKey, setShowPrivateKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [kemTestResult, setKemTestResult] = useState<KemRoundTripResult | null>(null);
  const [sigMessage, setSigMessage] = useState<string>(
    'QuantumShield FIPS 204 Attestation Payload'
  );
  const [sigTestResult, setSigTestResult] = useState<SignatureRoundTripResult | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);

  useEffect(() => {
    if (preselectedAlgorithm) {
      setSelectedAlgo(preselectedAlgorithm);
    }
  }, [preselectedAlgorithm]);

  // Live TLS Scanner State
  const [targetHost, setTargetHost] = useState<string>('nist.gov');
  const [targetPort, setTargetPort] = useState<number>(443);
  const [recordInInventory, setRecordInInventory] = useState<boolean>(true);
  const [isScanningHost, setIsScanningHost] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<TLSScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // CBOM State
  const [showManifestImporter, setShowManifestImporter] = useState<boolean>(false);
  const [manifestType, setManifestType] = useState<
    'package.json' | 'requirements.txt' | 'go.mod' | 'Cargo.toml'
  >('package.json');
  const [manifestText, setManifestText] = useState<string>('');
  const [cbomError, setCbomError] = useState<string | null>(null);
  const [isParsingCbom, setIsParsingCbom] = useState<boolean>(false);

  // Policy Scanner State
  const [codeInput, setCodeInput] = useState<string>('');
  const [policyFindings, setPolicyFindings] = useState<PolicyFinding[]>(workspaceFindings);
  const [policySourceLabel, setPolicySourceLabel] = useState<string>(
    'Live Workspace Source Scan'
  );
  const [isScanningPolicy, setIsScanningPolicy] = useState<boolean>(false);
  const [policyError, setPolicyError] = useState<string | null>(null);

  useEffect(() => {
    if (!codeInput) {
      setPolicyFindings(workspaceFindings);
      setPolicySourceLabel('Live Workspace Source Scan');
    }
  }, [workspaceFindings, codeInput]);

  const currentAlgoMeta = PQC_ALGORITHM_CATALOG[selectedAlgo];

  const handleGenerateKey = async () => {
    setIsGeneratingKey(true);
    setKeyError(null);
    setKemTestResult(null);
    setSigTestResult(null);
    setShowPrivateKey(false);
    try {
      const kp = await generatePqcKeyPair(selectedAlgo);
      setGeneratedKey(kp);
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : 'Key generation failed.');
    } finally {
      setIsGeneratingKey(false);
    }
  };

  const handleVerifyKem = async () => {
    if (!generatedKey || generatedKey.kind !== 'KEM') return;
    setKeyError(null);
    try {
      const res = await verifyKemRoundTrip(
        generatedKey.algorithmId,
        generatedKey.publicKey,
        generatedKey.secretKey
      );
      setKemTestResult(res);
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : 'KEM round-trip failed.');
    }
  };

  const handleVerifySignature = () => {
    if (!generatedKey || generatedKey.kind !== 'SIGNATURE') return;
    setKeyError(null);
    try {
      const res = verifySignatureRoundTrip(
        generatedKey.algorithmId,
        sigMessage,
        generatedKey.publicKey,
        generatedKey.secretKey
      );
      setSigTestResult(res);
    } catch (err) {
      setKeyError(err instanceof Error ? err.message : 'Signature verification failed.');
    }
  };

  const handleCopyKey = async () => {
    if (!generatedKey) return;
    await navigator.clipboard.writeText(generatedKey.publicKeyPem);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleDownloadPem = (pem: string, suffix: string) => {
    const blob = new Blob([pem], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedAlgo}_${suffix}.pem`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleRunTlsScan = async (overrideHost?: string) => {
    const hostToScan = (overrideHost ?? targetHost).trim();
    if (!hostToScan) return;
    setIsScanningHost(true);
    setScanError(null);

    try {
      const resp = await fetch('/api/tls-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: hostToScan,
          port: targetPort,
          recordInInventory,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'TLS scan failed.');
      }
      setScanResult(data as TLSScanResult);
      if (recordInInventory) {
        await onTlsAssetRecorded();
      }
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Unable to complete live TLS handshake.');
    } finally {
      setIsScanningHost(false);
    }
  };

  const handleParseCustomManifest = async (e: React.FormEvent) => {
    e.preventDefault();
    setCbomError(null);
    setIsParsingCbom(true);
    try {
      const resp = await fetch('/api/cbom/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifestType, content: manifestText }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to parse manifest.');
      }
      onUpdateCbomEntries(data.entries);
      setShowManifestImporter(false);
    } catch (err) {
      setCbomError(err instanceof Error ? err.message : 'Manifest parsing failed.');
    } finally {
      setIsParsingCbom(false);
    }
  };

  const handleResetWorkspaceCbom = async () => {
    setCbomError(null);
    const resp = await fetch('/api/cbom');
    if (resp.ok) {
      const data = await resp.json();
      onUpdateCbomEntries(data.entries);
    }
  };

  const handleExportCycloneDX = () => {
    const cycloneDxReport = buildCycloneDxCbom(cbomEntries);
    const blob = new Blob([JSON.stringify(cycloneDxReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `crypto_sbom_cyclonedx_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleRunPolicyScan = async () => {
    if (!codeInput.trim()) {
      setPolicyFindings(workspaceFindings);
      setPolicySourceLabel('Live Workspace Source Scan');
      return;
    }
    setIsScanningPolicy(true);
    setPolicyError(null);
    try {
      const resp = await fetch('/api/policy-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: codeInput, fileName: 'submitted-snippet' }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || 'Policy scan failed.');
      }
      setPolicyFindings(data.findings);
      setPolicySourceLabel('Submitted Code / Configuration');
    } catch (err) {
      setPolicyError(err instanceof Error ? err.message : 'Policy scan error.');
    } finally {
      setIsScanningPolicy(false);
    }
  };

  const handlePolicyFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setCodeInput(text);
    setIsScanningPolicy(true);
    setPolicyError(null);
    try {
      const resp = await fetch('/api/policy-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text, fileName: file.name }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Scan failed');
      setPolicyFindings(data.findings);
      setPolicySourceLabel(`Uploaded File: ${file.name}`);
    } catch (err) {
      setPolicyError(err instanceof Error ? err.message : 'Failed to scan uploaded file.');
    } finally {
      setIsScanningPolicy(false);
    }
  };

  const q = searchQuery.trim().toLowerCase();
  const filteredCbom = q
    ? cbomEntries.filter(
        (c) =>
          c.component.toLowerCase().includes(q) ||
          c.algorithm.toLowerCase().includes(q) ||
          c.nistStandard.toLowerCase().includes(q)
      )
    : cbomEntries;

  const severityColor = (sev: RiskLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-rose-400';
      case 'HIGH':
        return 'text-amber-400';
      case 'MEDIUM':
        return 'text-yellow-400';
      case 'LOW':
        return 'text-blue-400';
      case 'COMPLIANT':
        return 'text-emerald-400';
    }
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
            Live NIST FIPS 203/204/205 key synthesis, real TLS/X.509 probing, CycloneDX CBOM, and
            static CWE policy auditing.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-950 rounded-lg border border-slate-800">
          <button
            onClick={() => onSelectSubModule('key-generator')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 whitespace-nowrap ${
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
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 whitespace-nowrap ${
              activeSubModule === 'tls-scanner'
                ? 'bg-slate-800 text-cyan-400 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Live TLS Scanner</span>
          </button>

          <button
            onClick={() => onSelectSubModule('cbom')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 whitespace-nowrap ${
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
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors inline-flex items-center gap-2 whitespace-nowrap ${
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

      {/* MODULE 1: Real PQC Key Generator */}
      {activeSubModule === 'key-generator' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5">
            <div>
              <h2 className="text-base font-bold text-white">Post-Quantum Key Synthesizer</h2>
              <p className="text-xs text-slate-400 mt-1">
                Cryptographically genuine keypairs generated locally via Web Crypto CSPRNG and
                @noble/post-quantum (FIPS 203/204/205).
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <label htmlFor="pqc-algo-select" className="text-xs font-medium text-slate-300">
                  Target Post-Quantum Algorithm
                </label>
                <select
                  id="pqc-algo-select"
                  value={selectedAlgo}
                  onChange={(e) => setSelectedAlgo(e.target.value as PqcAlgorithmId)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <option value="ml-kem-512">ML-KEM-512 (FIPS 203) · NIST Level 1</option>
                  <option value="ml-kem-768">ML-KEM-768 (FIPS 203) · NIST Level 3</option>
                  <option value="ml-kem-1024">ML-KEM-1024 (FIPS 203 / CNSA 2.0) · Level 5</option>
                  <option value="ml-kem-768-x25519">
                    X25519 + ML-KEM-768 Hybrid · Defense-in-Depth
                  </option>
                  <option value="ml-dsa-44">ML-DSA-44 (FIPS 204) · NIST Level 2</option>
                  <option value="ml-dsa-65">ML-DSA-65 (FIPS 204) · NIST Level 3</option>
                  <option value="ml-dsa-87">ML-DSA-87 (FIPS 204 / CNSA 2.0) · Level 5</option>
                  <option value="slh-dsa-sha2-128f">
                    SLH-DSA-SHA2-128f (FIPS 205) · Hash Level 1
                  </option>
                  <option value="slh-dsa-sha2-256f">
                    SLH-DSA-SHA2-256f (FIPS 205) · Hash Level 5
                  </option>
                </select>
              </div>

              <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 space-y-1.5 text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Standard:</span>
                  <span className="text-emerald-400 font-mono">{currentAlgoMeta.fipsStandard}</span>
                </div>
                <div className="flex justify-between">
                  <span>Math Basis:</span>
                  <span className="text-slate-200 font-mono">{currentAlgoMeta.mathBasis}</span>
                </div>
                <div className="flex justify-between">
                  <span>Primitive Kind:</span>
                  <span className="text-slate-200 font-mono">{currentAlgoMeta.kind}</span>
                </div>
              </div>

              <button
                onClick={handleGenerateKey}
                disabled={isGeneratingKey}
                className="w-full py-2.5 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
              >
                <Play className={`w-3.5 h-3.5 ${isGeneratingKey ? 'animate-spin' : ''}`} />
                <span>
                  {isGeneratingKey ? 'Generating CSPRNG Keypair...' : 'Generate PQC Keypair'}
                </span>
              </button>

              {keyError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                  {keyError}
                </div>
              )}
            </div>
          </div>

          <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-white">
                  Cryptographic Key Material & Round-Trip Verification
                </h2>
                <p className="text-xs text-slate-400">
                  Real Base64-encoded public/private keys generated in-browser (never transmitted)
                </p>
              </div>

              {generatedKey && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyKey}
                    className="px-2.5 py-1.5 text-slate-300 hover:text-white bg-slate-800 rounded border border-slate-700 text-xs inline-flex items-center gap-1.5 transition-colors"
                  >
                    {copiedKey ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span>{copiedKey ? 'Copied' : 'Copy Public'}</span>
                  </button>
                  <button
                    onClick={() => handleDownloadPem(generatedKey.publicKeyPem, 'public')}
                    className="px-2.5 py-1.5 text-slate-300 hover:text-white bg-slate-800 rounded border border-slate-700 text-xs inline-flex items-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Public PEM</span>
                  </button>
                  <button
                    onClick={() => handleDownloadPem(generatedKey.privateKeyPem, 'private')}
                    className="px-2.5 py-1.5 text-amber-300 hover:text-amber-200 bg-slate-800 rounded border border-slate-700 text-xs inline-flex items-center gap-1.5 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Private PEM</span>
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
                    <span className="text-slate-500 font-mono text-[10px] block">PUBLIC / SECRET</span>
                    <span className="text-slate-200 font-mono font-semibold tabular-nums block">
                      {generatedKey.publicKeyBytes}B / {generatedKey.secretKeyBytes}B
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] block">HORIZON</span>
                    <span className="text-emerald-400 font-mono font-semibold truncate block">
                      {generatedKey.estimatedLifetime}
                    </span>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                    <span className="text-slate-400">
                      SHA-256 FINGERPRINT:{' '}
                      <span className="text-slate-200">{generatedKey.fingerprint}</span>
                    </span>
                    <button
                      onClick={() => setShowPrivateKey(!showPrivateKey)}
                      className="text-amber-400 hover:text-amber-300 inline-flex items-center gap-1"
                    >
                      {showPrivateKey ? (
                        <EyeOff className="w-3.5 h-3.5" />
                      ) : (
                        <Eye className="w-3.5 h-3.5" />
                      )}
                      <span>{showPrivateKey ? 'Hide Private Key' : 'Reveal Private Key'}</span>
                    </button>
                  </div>

                  <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto max-h-48 leading-relaxed select-all">
                    {generatedKey.publicKeyPem}
                  </pre>

                  {showPrivateKey && (
                    <pre className="p-4 bg-slate-950 rounded-lg border border-amber-500/30 font-mono text-xs text-amber-300 overflow-x-auto max-h-48 leading-relaxed select-all">
                      {generatedKey.privateKeyPem}
                    </pre>
                  )}
                </div>

                {/* Live Cryptographic Self-Test */}
                <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <h3 className="text-xs font-semibold text-white">
                        Live Cryptographic Operation Verification
                      </h3>
                      <p className="text-[11px] text-slate-400">
                        {generatedKey.kind === 'KEM'
                          ? 'Execute real ML-KEM encapsulation and decapsulation to verify shared secret agreement.'
                          : 'Sign an arbitrary payload and cryptographically verify the signature with the public key.'}
                      </p>
                    </div>
                    {generatedKey.kind === 'KEM' ? (
                      <button
                        onClick={handleVerifyKem}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-emerald-400 rounded-md border border-slate-700 inline-flex items-center gap-1.5 whitespace-nowrap"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Encapsulate & Verify</span>
                      </button>
                    ) : (
                      <button
                        onClick={handleVerifySignature}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-emerald-400 rounded-md border border-slate-700 inline-flex items-center gap-1.5 whitespace-nowrap"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Sign & Verify</span>
                      </button>
                    )}
                  </div>

                  {generatedKey.kind === 'SIGNATURE' && (
                    <input
                      type="text"
                      value={sigMessage}
                      onChange={(e) => setSigMessage(e.target.value)}
                      placeholder="Payload to sign..."
                      className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-1.5 text-xs font-mono text-slate-200"
                    />
                  )}

                  {kemTestResult && (
                    <div className="text-xs font-mono text-emerald-300 space-y-1 pt-1 border-t border-slate-800">
                      <div>
                        Status: {kemTestResult.verified ? 'VERIFIED (Shared secrets match)' : 'FAILED'}
                      </div>
                      <div className="text-slate-400">
                        Ciphertext: {kemTestResult.cipherTextBytes} bytes · Shared Secret:{' '}
                        {kemTestResult.sharedSecretBytes} bytes
                      </div>
                      <div className="text-slate-400 truncate">
                        Secret SHA-256: {kemTestResult.sharedSecretSha256}
                      </div>
                    </div>
                  )}

                  {sigTestResult && (
                    <div className="text-xs font-mono text-emerald-300 space-y-1 pt-1 border-t border-slate-800">
                      <div>
                        Signature Verification:{' '}
                        {sigTestResult.verified ? 'VALID (Authentic)' : 'INVALID'}
                      </div>
                      <div className="text-slate-400">
                        Signature Length: {sigTestResult.signatureBytes} bytes · Preview:{' '}
                        {sigTestResult.signatureHexPreview}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-12 text-center border border-dashed border-slate-800 rounded-lg space-y-3">
                <KeyRound className="w-8 h-8 text-slate-600 mx-auto" />
                <div className="text-sm font-medium text-slate-300">No Keypair Generated Yet</div>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Select a standardized NIST FIPS 203, 204, or 205 algorithm and generate a real
                  cryptographic keypair.
                </p>
                <button
                  onClick={handleGenerateKey}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 rounded-lg border border-slate-700"
                >
                  Generate ML-KEM-768 Keypair
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODULE 2: Live Quantum TLS Scanner */}
      {activeSubModule === 'tls-scanner' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <h2 className="text-base font-bold text-white">Live TLS / X.509 Quantum Readiness Audit</h2>
            <p className="text-xs text-slate-400">
              Executes a live DNS lookup, TLS handshake, and X.509 certificate inspection from the
              server to evaluate key exchange groups, cipher suites, and certificate signatures.
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Radio className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  placeholder="Enter public FQDN (e.g. nist.gov, cloudflare.com)"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <input
                type="number"
                min={1}
                max={65535}
                value={targetPort}
                onChange={(e) => setTargetPort(Number(e.target.value) || 443)}
                aria-label="TLS Port"
                className="w-24 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />

              <button
                onClick={() => handleRunTlsScan()}
                disabled={isScanningHost}
                className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 whitespace-nowrap"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isScanningHost ? 'animate-spin' : ''}`} />
                <span>{isScanningHost ? 'Handshaking...' : 'Scan Live Host'}</span>
              </button>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-slate-500">Public Targets:</span>
                {PUBLIC_TLS_PRESETS.map((host) => (
                  <button
                    key={host}
                    onClick={() => {
                      setTargetHost(host);
                      setTargetPort(443);
                      handleRunTlsScan(host);
                    }}
                    className="text-xs font-mono text-slate-300 hover:text-cyan-400 underline decoration-slate-700"
                  >
                    {host}
                  </button>
                ))}
              </div>

              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={recordInInventory}
                  onChange={(e) => setRecordInInventory(e.target.checked)}
                  className="accent-cyan-400 rounded"
                />
                <span>Record scanned host in Risk Matrix</span>
              </label>
            </div>

            {scanError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{scanError}</span>
              </div>
            )}
          </div>

          {scanResult && (
            <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-white font-mono">
                      {scanResult.host}:{scanResult.port}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">({scanResult.ip})</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5 font-mono">
                    {scanResult.tlsVersion} · {scanResult.cipherSuite} · {scanResult.latencyMs}ms
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">
                      QUANTUM GRADE
                    </span>
                    <span
                      className={`text-2xl font-bold font-mono ${
                        scanResult.quantumSafeGrade.startsWith('A')
                          ? 'text-emerald-400'
                          : scanResult.quantumSafeGrade === 'B'
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }`}
                    >
                      {scanResult.quantumSafeGrade}
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">
                      SAFETY SCORE
                    </span>
                    <span className="text-2xl font-bold font-mono text-white tabular-nums">
                      {scanResult.quantumSafetyScore}
                      <span className="text-xs text-slate-500">/100</span>
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Negotiated Key Exchange
                  </span>
                  <div className="text-slate-200 font-semibold">{scanResult.keyExchange}</div>
                  <div
                    className={`text-[11px] ${
                      scanResult.isHybridPQC ? 'text-emerald-400' : 'text-rose-400'
                    }`}
                  >
                    {scanResult.isHybridPQC
                      ? 'Post-quantum hybrid key agreement active'
                      : 'Classical key exchange vulnerable to SNDL harvesting'}
                  </div>
                </div>

                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Certificate Signature Scheme
                  </span>
                  <div className="text-slate-200 font-semibold">
                    {scanResult.signatureAlgorithm}
                  </div>
                  {scanResult.certificate && (
                    <div className="text-[11px] text-slate-400">
                      Key: {scanResult.certificate.publicKeyType}{' '}
                      {scanResult.certificate.publicKeyBits
                        ? `${scanResult.certificate.publicKeyBits}-bit`
                        : ''}{' '}
                      · Expires in {scanResult.certificate.daysRemaining} days
                    </div>
                  )}
                </div>
              </div>

              {scanResult.certificate && (
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono space-y-1.5">
                  <div className="text-slate-400 text-[10px] uppercase">
                    Live Peer X.509 Certificate Metadata
                  </div>
                  <div className="text-slate-300 truncate">
                    Subject: <span className="text-slate-100">{scanResult.certificate.subject}</span>
                  </div>
                  <div className="text-slate-300 truncate">
                    Issuer: <span className="text-slate-100">{scanResult.certificate.issuer}</span>
                  </div>
                  <div className="text-slate-400 truncate">
                    SHA-256: {scanResult.certificate.fingerprint256}
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <h3 className="text-xs font-bold text-slate-200 uppercase font-mono">
                  Remediation Recommendations
                </h3>
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

      {/* MODULE 3: Live Cryptographic SBOM (CBOM) */}
      {activeSubModule === 'cbom' && (
        <div className="space-y-4">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-white">
                Cryptographic Bill of Materials (CBOM)
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Live dependency classification from package manifests, exportable as CycloneDX 1.5
                JSON.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                onClick={() => setShowManifestImporter(!showManifestImporter)}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg border border-slate-700 transition-colors inline-flex items-center gap-2"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Parse Manifest</span>
              </button>
              <button
                onClick={handleResetWorkspaceCbom}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs rounded-lg border border-slate-700 transition-colors"
              >
                Workspace Default
              </button>
              <button
                onClick={handleExportCycloneDX}
                className="px-3.5 py-2 bg-purple-500 hover:bg-purple-400 text-white font-semibold text-xs rounded-lg transition-colors inline-flex items-center gap-2"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>Export CycloneDX 1.5</span>
              </button>
            </div>
          </div>

          {showManifestImporter && (
            <form
              onSubmit={handleParseCustomManifest}
              className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="text-xs font-semibold text-white">
                  Analyze External Dependency Manifest
                </label>
                <select
                  value={manifestType}
                  onChange={(e) => setManifestType(e.target.value as typeof manifestType)}
                  className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1 text-xs text-slate-200 font-mono"
                >
                  <option value="package.json">package.json (Node.js)</option>
                  <option value="requirements.txt">requirements.txt (Python)</option>
                  <option value="go.mod">go.mod (Go)</option>
                  <option value="Cargo.toml">Cargo.toml (Rust)</option>
                </select>
              </div>
              <textarea
                value={manifestText}
                onChange={(e) => setManifestText(e.target.value)}
                rows={6}
                placeholder={`Paste contents of ${manifestType}...`}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200"
              />
              {cbomError && <div className="text-xs text-rose-400">{cbomError}</div>}
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowManifestImporter(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isParsingCbom}
                  className="px-3.5 py-1.5 bg-purple-500 hover:bg-purple-400 text-white text-xs font-semibold rounded-md disabled:opacity-50"
                >
                  {isParsingCbom ? 'Parsing...' : 'Generate CBOM'}
                </button>
              </div>
            </form>
          )}

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px]">
                    <th className="py-3 px-4 font-medium">COMPONENT</th>
                    <th className="py-3 px-4 font-medium">VERSION</th>
                    <th className="py-3 px-4 font-medium">CRYPTOGRAPHIC PRIMITIVES</th>
                    <th className="py-3 px-4 font-medium">PURPOSE</th>
                    <th className="py-3 px-4 font-medium">RISK LEVEL</th>
                    <th className="py-3 px-4 font-medium">STANDARD / STATUS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredCbom.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono font-semibold text-slate-200">
                        {entry.component}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">{entry.version}</td>
                      <td className="py-3 px-4 font-mono text-slate-300">{entry.algorithm}</td>
                      <td className="py-3 px-4 text-slate-400">{entry.purpose}</td>
                      <td className="py-3 px-4">
                        <span className={`font-mono text-xs font-semibold ${severityColor(entry.riskLevel)}`}>
                          [{entry.riskLevel}]
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{entry.nistStandard}</td>
                    </tr>
                  ))}
                  {filteredCbom.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400">
                        No cryptographic dependencies found in this manifest matching the filter.
                      </td>
                    </tr>
                  )}
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
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-bold text-white">
                  Cryptographic Policy & Code Linter
                </h2>
                <p className="text-xs text-slate-400">
                  CWE-326 / CWE-327 / CWE-328 / CWE-338 static analyzer (defaults to live
                  workspace scan)
                </p>
              </div>
              <div className="flex items-center gap-2">
                <label className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 cursor-pointer inline-flex items-center gap-1.5">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload File</span>
                  <input
                    type="file"
                    accept=".ts,.tsx,.js,.py,.go,.rs,.conf,.env,.yaml,.yml,.json,.toml,.txt"
                    onChange={handlePolicyFileUpload}
                    className="hidden"
                  />
                </label>
                <button
                  onClick={handleRunPolicyScan}
                  disabled={isScanningPolicy}
                  className="px-3.5 py-1.5 bg-amber-400 hover:bg-amber-300 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>{codeInput.trim() ? 'Audit Snippet' : 'Show Workspace Scan'}</span>
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="policy-code-input" className="text-xs font-medium text-slate-300 font-mono">
                PASTE SOURCE OR CONFIGURATION TO AUDIT (LEAVE EMPTY FOR LIVE WORKSPACE RESULTS):
              </label>
              <textarea
                id="policy-code-input"
                value={codeInput}
                onChange={(e) => setCodeInput(e.target.value)}
                rows={11}
                placeholder="Paste nginx.conf, .env, Python/TypeScript/Go source code, or TLS policy config..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:ring-1 focus:ring-amber-500 leading-relaxed"
              />
              {policyError && <div className="text-xs text-rose-400">{policyError}</div>}
            </div>
          </div>

          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-sm font-bold text-white">
                Policy Compliance Findings ({policyFindings.length})
              </h2>
              <span className="text-[11px] font-mono text-slate-400">{policySourceLabel}</span>
            </div>

            <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
              {policyFindings.map((finding, idx) => (
                <div
                  key={`${finding.ruleId}-${finding.line}-${idx}`}
                  className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={`font-mono font-semibold ${severityColor(finding.severity)}`}>
                      {finding.file ? `${finding.file}:` : ''}L{finding.line}:{finding.column} —{' '}
                      {finding.rule}
                    </span>
                    <span className={`font-mono text-[10px] shrink-0 ${severityColor(finding.severity)}`}>
                      [{finding.severity}]
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500">
                    {finding.ruleId} · {finding.cwe} · {finding.standard}
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    <strong className="text-slate-300">Remediation:</strong> {finding.fix}
                  </p>
                </div>
              ))}
              {policyFindings.length === 0 && (
                <div className="p-8 text-center text-emerald-400 font-mono text-xs">
                  Clean: Zero cryptographic policy violations detected in {policySourceLabel}.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
