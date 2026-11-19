import React from 'react';
import { 
  ShieldAlert, 
  KeyRound, 
  Clock, 
  AlertTriangle, 
  Layers, 
  Radio, 
  ArrowUpRight, 
  TrendingUp,
  FileCheck2,
  LockKeyhole
} from 'lucide-react';
import { CryptoAsset, MigrationMilestone, NavigationSection, SecuritySubModule } from '../../types/quantum';

interface OverviewSectionProps {
  assets: CryptoAsset[];
  milestones: MigrationMilestone[];
  onNavigateSection: (section: NavigationSection) => void;
  onNavigateSubModule: (sub: SecuritySubModule) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({
  assets,
  milestones,
  onNavigateSection,
  onNavigateSubModule,
}) => {
  const criticalAssets = assets.filter((a) => a.quantumRisk === 'CRITICAL');
  const highAssets = assets.filter((a) => a.quantumRisk === 'HIGH');
  const compliantAssets = assets.filter((a) => a.quantumRisk === 'COMPLIANT' || a.quantumRisk === 'LOW');
  
  const totalAssets = assets.length;
  const readyPercent = Math.round((compliantAssets.length / totalAssets) * 100);
  const vulnerablePercent = Math.round(((criticalAssets.length + highAssets.length) / totalAssets) * 100);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Banner / Welcome context */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Governance Workspace</span>
            <span aria-hidden="true">·</span>
            <span>Cryptographic Inventory CBOM v2.4</span>
            <span aria-hidden="true">·</span>
            <span>FIPS 203 / 204 Audited</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
            Post-Quantum Cryptography & Risk Posture
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-2xl">
            Evaluate enterprise cryptographic primitives against quantum computing timelines. Audit Shor's and Grover's algorithm exposure across internal PKI, cloud gateways, and TLS ciphers.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => onNavigateSection('risk-analysis')}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 text-xs font-semibold text-slate-200 rounded-lg transition-colors inline-flex items-center gap-2"
          >
            <span>Run Risk Matrix</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
          </button>
          <button
            onClick={() => onNavigateSubModule('key-generator')}
            className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-xs font-semibold text-slate-950 rounded-lg transition-colors inline-flex items-center gap-2"
          >
            <span>Generate PQC Keypair</span>
            <KeyRound className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Audited Primitives</span>
            <LockKeyhole className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold text-white font-mono tabular-nums">
            {totalAssets}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Certificates, keys, tunnels</span>
            <span>·</span>
            <span className="text-emerald-400 font-mono">100% indexed</span>
          </div>
        </div>

        {/* Quantum Vulnerable */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Quantum Vulnerable</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono tabular-nums">
            {criticalAssets.length + highAssets.length}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span className="text-rose-400 font-semibold">{vulnerablePercent}%</span>
            <span>exposed to Shor factoring</span>
          </div>
        </div>

        {/* Post-Quantum Ready */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>PQC Readiness Rate</span>
            <TrendingUp className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono tabular-nums">
            {readyPercent}%
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>{compliantAssets.length} resilient primitives</span>
            <span>·</span>
            <span>FIPS 203 ready</span>
          </div>
        </div>

        {/* Target Milestone */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>CNSA 2.0 Hard Deadline</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono tabular-nums">
            2030 - 2033
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Mandatory federal phase-out</span>
          </div>
        </div>
      </div>

      {/* Split section: High Priority Vulnerabilities & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: High-Priority Attention List (2 columns on wide) */}
        <div className="lg:col-span-2 p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Vulnerable Cryptographic Assets Requiring Remediation
              </h2>
              <p className="text-xs text-slate-400">
                Primitives vulnerable to Store Now, Decrypt Later (SNDL) attacks
              </p>
            </div>
            <button
              onClick={() => onNavigateSection('risk-analysis')}
              className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 transition-colors inline-flex items-center gap-1"
            >
              <span>View Matrix</span>
              <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3">
            {criticalAssets.map((asset) => (
              <div
                key={asset.id}
                className="p-3.5 bg-slate-950/60 border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-rose-400 font-semibold">
                      [CRITICAL RISK]
                    </span>
                    <span className="font-medium text-xs text-slate-200 truncate">
                      {asset.name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400">
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
                    <span className="text-[10px] text-slate-500 uppercase block font-mono">
                      Target Replacement
                    </span>
                    <span className="text-xs font-mono text-emerald-400 font-medium">
                      {asset.recommendedPQC}
                    </span>
                  </div>
                  <button
                    onClick={() => onNavigateSubModule('key-generator')}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 rounded border border-slate-700 transition-colors whitespace-nowrap"
                  >
                    Simulate Migration
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Security Modules Launchpad */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-white">Security Engines Launchpad</h2>
            <p className="text-xs text-slate-400">Interactive operational tools</p>
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
                    Generate ML-KEM & ML-DSA keypairs
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
                    Quantum TLS Scanner
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    Audit host cipher suites & KEM exchange
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
                    CycloneDX 1.5 cryptographic inventory
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
                    Policy & Deprecated Crypto
                  </span>
                  <span className="text-[11px] text-slate-400 block truncate">
                    Detect MD5, SHA1, and weak RSA curves
                  </span>
                </div>
              </div>
              <ArrowUpRight className="w-4 h-4 text-slate-500 group-hover:text-amber-400 shrink-0" />
            </button>
          </div>
        </div>
      </div>

      {/* NIST PQC Roadmap & Transition Milestones */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">NIST & CNSA 2.0 PQC Migration Roadmap</h2>
            <p className="text-xs text-slate-400">Federal mandates, algorithm standards, and deprecation horizons</p>
          </div>
          <span className="text-xs font-mono text-emerald-400">Official Standards FIPS 203/204/205</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
          {milestones.map((m, idx) => (
            <div
              key={m.year}
              className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2 relative"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold font-mono text-emerald-400 tabular-nums">
                  {m.year}
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  {m.status}
                </span>
              </div>
              <h3 className="text-xs font-semibold text-slate-200 leading-tight">
                {m.title}
              </h3>
              <p className="text-[11px] text-slate-400 line-clamp-3">
                {m.impactSummary}
              </p>
              <div className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-850">
                {m.organization}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
