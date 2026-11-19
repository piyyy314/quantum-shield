import React from 'react';
import {
  ShieldAlert,
  KeyRound,
  Clock,
  Layers,
  Radio,
  ArrowUpRight,
  TrendingUp,
  FileCheck2,
  LockKeyhole,
  CheckCircle2,
} from 'lucide-react';
import type {
  CryptoAsset,
  MigrationMilestone,
  NavigationSection,
  RuntimeEnvironmentInfo,
  SecuritySubModule,
} from '../../types/quantum';
import type { PqcAlgorithmId } from '../../engine/pqcCrypto';

interface OverviewSectionProps {
  assets: CryptoAsset[];
  milestones: MigrationMilestone[];
  runtime: RuntimeEnvironmentInfo | null;
  lastAuditedAt: string | null;
  workspaceFilesScanned: number;
  cbomCount: number;
  isLoading: boolean;
  searchQuery: string;
  onNavigateSection: (section: NavigationSection) => void;
  onNavigateSubModule: (sub: SecuritySubModule, preselectAlgo?: PqcAlgorithmId) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({
  assets,
  milestones,
  runtime,
  lastAuditedAt,
  workspaceFilesScanned,
  cbomCount,
  isLoading,
  searchQuery,
  onNavigateSection,
  onNavigateSubModule,
}) => {
  const query = searchQuery.trim().toLowerCase();
  const scopedAssets = query
    ? assets.filter(
        (a) =>
          a.name.toLowerCase().includes(query) ||
          a.algorithm.toLowerCase().includes(query) ||
          a.system.toLowerCase().includes(query)
      )
    : assets;

  const criticalAssets = scopedAssets.filter((a) => a.quantumRisk === 'CRITICAL');
  const highAssets = scopedAssets.filter((a) => a.quantumRisk === 'HIGH');
  const remediationQueue = [...criticalAssets, ...highAssets];
  const compliantAssets = scopedAssets.filter(
    (a) => a.quantumRisk === 'COMPLIANT' || a.quantumRisk === 'LOW'
  );

  const totalAssets = scopedAssets.length;
  const readyPercent = totalAssets > 0 ? Math.round((compliantAssets.length / totalAssets) * 100) : 0;
  const vulnerablePercent =
    totalAssets > 0 ? Math.round((remediationQueue.length / totalAssets) * 100) : 0;

  const inferRecommendedAlgoId = (recommendedPQC: string): PqcAlgorithmId => {
    const upper = recommendedPQC.toUpperCase();
    if (upper.includes('ML-DSA-87')) return 'ml-dsa-87';
    if (upper.includes('ML-DSA')) return 'ml-dsa-65';
    if (upper.includes('SLH-DSA')) return 'slh-dsa-sha2-128f';
    if (upper.includes('ML-KEM-1024')) return 'ml-kem-1024';
    if (upper.includes('X25519')) return 'ml-kem-768-x25519';
    return 'ml-kem-768';
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span>Live Cryptographic Governance</span>
            <span aria-hidden="true">·</span>
            <span>{workspaceFilesScanned} workspace files indexed</span>
            <span aria-hidden="true">·</span>
            <span>
              {lastAuditedAt
                ? `Last audited ${new Date(lastAuditedAt).toLocaleTimeString()}`
                : runtime
                ? `OpenSSL ${runtime.opensslVersion}`
                : 'Initializing runtime audit'}
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
            Post-Quantum Cryptography & Risk Posture
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-2xl">
            Live cryptographic posture across the Node.js/OpenSSL runtime, workspace dependencies,
            and scanned TLS endpoints evaluated against NIST FIPS 203/204/205 and NSA CNSA 2.0.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => onNavigateSection('risk-analysis')}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 text-xs font-semibold text-slate-200 rounded-lg transition-colors inline-flex items-center gap-2 whitespace-nowrap"
          >
            <span>Open Risk Matrix</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
          </button>
          <button
            onClick={() => onNavigateSubModule('key-generator')}
            className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-xs font-semibold text-slate-950 rounded-lg transition-colors inline-flex items-center gap-2 whitespace-nowrap"
          >
            <span>Generate PQC Keypair</span>
            <KeyRound className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Discovered Primitives</span>
            <LockKeyhole className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {isLoading ? '—' : totalAssets}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>{cbomCount} CBOM dependencies</span>
            <span aria-hidden="true">·</span>
            <span className="text-emerald-400 font-mono">Live inventory</span>
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Quantum Vulnerable</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono tabular-nums">
            {isLoading ? '—' : remediationQueue.length}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span className="text-rose-400 font-semibold font-mono tabular-nums">
              {vulnerablePercent}%
            </span>
            <span>require PQC transition</span>
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>PQC Readiness Rate</span>
            <TrendingUp className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono tabular-nums">
            {isLoading ? '—' : `${readyPercent}%`}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>{compliantAssets.length} compliant primitives</span>
            <span aria-hidden="true">·</span>
            <span>FIPS 203/204/205</span>
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>CNSA 2.0 Hard Deadline</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono tabular-nums">
            2030–2033
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>NIST IR 8547 / OMB M-23-02</span>
          </div>
        </div>
      </div>

      {/* Split section: Remediation Queue & Security Engines Launchpad */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Vulnerable Cryptographic Assets Requiring Remediation
              </h2>
              <p className="text-xs text-slate-400">
                Discovered classical asymmetric primitives vulnerable to Shor factoring or SNDL
              </p>
            </div>
            <button
              onClick={() => onNavigateSection('risk-analysis')}
              className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 transition-colors inline-flex items-center gap-1 whitespace-nowrap"
            >
              <span>View Matrix</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>

          {remediationQueue.length > 0 ? (
            <div className="space-y-3">
              {remediationQueue.map((asset) => (
                <div
                  key={asset.id}
                  className="p-3.5 bg-slate-950/60 border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={`font-mono text-xs font-semibold shrink-0 ${
                          asset.quantumRisk === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                        }`}
                      >
                        [{asset.quantumRisk}]
                      </span>
                      <span className="font-medium text-xs text-slate-200 truncate">
                        {asset.name}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                      <span className="font-mono text-slate-300">
                        {asset.algorithm} ({asset.keySize}-bit)
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{asset.system}</span>
                      <span aria-hidden="true">·</span>
                      <span>Shelf-life: {asset.shelfLifeYears} yrs</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right hidden sm:block">
                      <span className="text-[10px] text-slate-500 block font-mono">
                        Target Replacement
                      </span>
                      <span className="text-xs font-mono text-emerald-400 font-medium">
                        {asset.recommendedPQC}
                      </span>
                    </div>
                    <button
                      onClick={() =>
                        onNavigateSubModule('key-generator', inferRecommendedAlgoId(asset.recommendedPQC))
                      }
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 rounded border border-slate-700 transition-colors whitespace-nowrap"
                    >
                      Generate PQC Key
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg space-y-2">
              <CheckCircle2 className="w-7 h-7 text-emerald-400 mx-auto" />
              <div className="text-sm font-medium text-slate-200">
                No Critical or High Quantum Vulnerabilities Found
              </div>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Scan a live TLS host or register additional endpoints in Quantum Risk Analysis to evaluate external infrastructure.
              </p>
              <button
                onClick={() => onNavigateSubModule('tls-scanner')}
                className="mt-2 px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-cyan-400 rounded-lg border border-slate-700"
              >
                Scan Live TLS Endpoint
              </button>
            </div>
          )}
        </div>

        {/* Security Modules Launchpad */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-white">Security Engines Launchpad</h2>
            <p className="text-xs text-slate-400">Live cryptographic verification tools</p>
          </div>

          <div className="space-y-2.5">
            <button
              onClick={() => onNavigateSubModule('key-generator')}
              className="w-full text-left p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-950 transition-colors flex items-center justify-between group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-400 block truncate">
                    PQC Key Generator
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    Real ML-KEM, ML-DSA & SLH-DSA keys
                  </span>
                </div>
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 shrink-0" />
            </button>

            <button
              onClick={() => onNavigateSubModule('tls-scanner')}
              className="w-full text-left p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-950 transition-colors flex items-center justify-between group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded bg-cyan-500/10 text-cyan-400 flex items-center justify-center shrink-0">
                  <Radio className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-400 block truncate">
                    Live TLS Scanner
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    Inspect real TLS 1.3 handshake & X.509
                  </span>
                </div>
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 shrink-0" />
            </button>

            <button
              onClick={() => onNavigateSubModule('cbom')}
              className="w-full text-left p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-purple-500/40 hover:bg-slate-950 transition-colors flex items-center justify-between group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded bg-purple-500/10 text-purple-400 flex items-center justify-center shrink-0">
                  <Layers className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-purple-400 block truncate">
                    Cryptographic SBOM
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    Live CycloneDX 1.5 dependency audit
                  </span>
                </div>
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 shrink-0" />
            </button>

            <button
              onClick={() => onNavigateSubModule('policy-scanner')}
              className="w-full text-left p-3 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-amber-500/40 hover:bg-slate-950 transition-colors flex items-center justify-between group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-8 h-8 rounded bg-amber-500/10 text-amber-400 flex items-center justify-center shrink-0">
                  <FileCheck2 className="w-4 h-4" />
                </div>
                <div className="truncate">
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-amber-400 block truncate">
                    Policy & Code Scanner
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    CWE-327/328/338 static crypto linter
                  </span>
                </div>
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-amber-400 shrink-0" />
            </button>
          </div>
        </div>
      </div>

      {/* NIST PQC Roadmap */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              NIST & CNSA 2.0 PQC Migration Roadmap
            </h2>
            <p className="text-xs text-slate-400">
              Official federal mandates, standardized algorithms, and deprecation timelines
            </p>
          </div>
          <span className="text-xs font-mono text-emerald-400">
            FIPS 203 / 204 / 205 · NSM-10
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
          {milestones.map((m) => (
            <div
              key={m.year}
              className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold font-mono text-emerald-400 tabular-nums">
                  {m.year}
                </span>
                <span className="text-[10px] font-mono text-slate-400">{m.status}</span>
              </div>
              <h3 className="text-xs font-semibold text-slate-200 leading-tight">{m.title}</h3>
              <p className="text-[11px] text-slate-400 line-clamp-3">{m.impactSummary}</p>
              <div className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800">
                {m.organization}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
