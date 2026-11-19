import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Search, 
  HelpCircle, 
  Sliders, 
  ArrowRight, 
  CheckCircle2, 
  XCircle, 
  Layers,
  Sparkles,
  Info
} from 'lucide-react';
import { CryptoAsset, AlgorithmProfile, RiskLevel } from '../../types/quantum';
import { ALGORITHM_PROFILES } from '../../data/mockQuantumData';

interface QuantumRiskAnalysisProps {
  assets: CryptoAsset[];
  searchQuery: string;
}

export const QuantumRiskAnalysisSection: React.FC<QuantumRiskAnalysisProps> = ({
  assets,
  searchQuery,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'matrix' | 'mosley-calculator' | 'algorithm-catalog'>('matrix');

  // Mosley's Theorem Calculator States
  // Theorem: If (Data Shelf-Life X + Migration Time Y) > (Years to CRQC Z), Risk is Immediate
  const [shelfLifeX, setShelfLifeX] = useState<number>(10);
  const [migrationTimeY, setMigrationTimeY] = useState<number>(3);
  const [crqcHorizonZ, setCrqcHorizonZ] = useState<number>(7);

  const totalExposureYears = shelfLifeX + migrationTimeY;
  const isBreached = totalExposureYears > crqcHorizonZ;
  const breachDeficit = totalExposureYears - crqcHorizonZ;

  // Filter assets
  const filteredAssets = assets.filter((asset) => {
    const matchesSearch =
      asset.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.algorithm.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.system.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;

    if (selectedCategory === 'all') return true;
    if (selectedCategory === 'asymmetric') return asset.primitiveType === 'Asymmetric';
    if (selectedCategory === 'symmetric') return asset.primitiveType === 'Symmetric';
    if (selectedCategory === 'pqc') return asset.primitiveType === 'PQC Native' || asset.primitiveType === 'PQC Hybrid';
    return true;
  });

  const getRiskBadge = (risk: RiskLevel) => {
    switch (risk) {
      case 'CRITICAL':
        return <span className="font-mono text-xs text-rose-400 font-semibold">[CRITICAL]</span>;
      case 'HIGH':
        return <span className="font-mono text-xs text-amber-400 font-semibold">[HIGH]</span>;
      case 'MEDIUM':
        return <span className="font-mono text-xs text-yellow-400 font-semibold">[MEDIUM]</span>;
      case 'LOW':
        return <span className="font-mono text-xs text-blue-400 font-semibold">[LOW]</span>;
      case 'COMPLIANT':
        return <span className="font-mono text-xs text-emerald-400 font-semibold">[COMPLIANT]</span>;
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header and Section Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-xl">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">
            Quantum Risk & Cryptographic Vulnerability Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Analyze Shor's & Grover's algorithm risk exposure across enterprise primitives and compute Mosley's theorem horizons.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 self-start sm:self-auto shrink-0">
          <button
            onClick={() => setActiveTab('matrix')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'matrix'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Asset Matrix
          </button>
          <button
            onClick={() => setActiveTab('mosley-calculator')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'mosley-calculator'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Mosley's Calculator (X+Y &gt; Z)
          </button>
          <button
            onClick={() => setActiveTab('algorithm-catalog')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'algorithm-catalog'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Algorithm Threat Profiles
          </button>
        </div>
      </div>

      {/* VIEW 1: Asset Matrix */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-mono">FILTER BY PRIMITIVE:</span>
              <div className="flex items-center gap-1">
                {[
                  { id: 'all', label: 'All' },
                  { id: 'asymmetric', label: 'Asymmetric (RSA / ECC)' },
                  { id: 'symmetric', label: 'Symmetric (AES / ChaCha)' },
                  { id: 'pqc', label: 'Post-Quantum (ML-KEM / DSA)' },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedCategory(cat.id)}
                    className={`px-2.5 py-1 rounded text-xs transition-colors ${
                      selectedCategory === cat.id
                        ? 'bg-slate-800 text-emerald-400 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="text-slate-400 font-mono text-[11px]">
              Showing <span className="text-slate-200 font-semibold">{filteredAssets.length}</span> of {assets.length} primitives
            </div>
          </div>

          {/* Table Container */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px]">
                    <th className="py-3 px-4 font-medium">CRYPTOGRAPHIC ASSET & SYSTEM</th>
                    <th className="py-3 px-4 font-medium">CURRENT ALGORITHM</th>
                    <th className="py-3 px-4 font-medium">QUANTUM RISK</th>
                    <th className="py-3 px-4 font-medium text-right">SHELF-LIFE (X)</th>
                    <th className="py-3 px-4 font-medium text-right">MIGRATION (Y)</th>
                    <th className="py-3 px-4 font-medium">RECOMMENDED PQC (NIST)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredAssets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">{asset.name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">{asset.system}</div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-mono text-slate-300 font-medium">
                          {asset.algorithm}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {asset.keySize}-bit · {asset.primitiveType}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5">
                          {getRiskBadge(asset.quantumRisk)}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                        {asset.shelfLifeYears} yrs
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-300">
                        {asset.migrationTimeMonths} mos
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-mono text-emerald-400 font-medium">
                          {asset.recommendedPQC}
                        </div>
                        <div className="text-[11px] text-slate-400 line-clamp-1">
                          {asset.notes}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredAssets.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400">
                        No cryptographic assets match your search or filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: Mosley's Theorem Risk Calculator */}
      {activeTab === 'mosley-calculator' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Controls Form */}
          <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6">
            <div>
              <h2 className="text-base font-bold text-white">
                Mosley's Theorem: Store Now, Decrypt Later (SNDL) Exposure
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Theorem formulated by Dr. Michele Mosca: If $(X + Y) &gt; Z$, your encrypted data will be compromised by a quantum computer before the end of its useful security lifetime.
              </p>
            </div>

            <div className="space-y-5">
              {/* Slider X */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-emerald-400 font-bold">[X]</span>
                    Data Shelf-Life (Confidentiality Requirement)
                  </label>
                  <span className="font-mono text-emerald-400 font-semibold tabular-nums">
                    {shelfLifeX} Years
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="30"
                  value={shelfLifeX}
                  onChange={(e) => setShelfLifeX(Number(e.target.value))}
                  className="w-full accent-emerald-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  How many years must this data remain strictly confidential (e.g. intellectual property, medical records, financial keys)?
                </p>
              </div>

              {/* Slider Y */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-blue-400 font-bold">[Y]</span>
                    Migration Timeframe (Deployment & Migration)
                  </label>
                  <span className="font-mono text-blue-400 font-semibold tabular-nums">
                    {migrationTimeY} Years
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={migrationTimeY}
                  onChange={(e) => setMigrationTimeY(Number(e.target.value))}
                  className="w-full accent-blue-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  How many years will it take your organization to fully deploy post-quantum algorithms across all endpoints and dependencies?
                </p>
              </div>

              {/* Slider Z */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-amber-400 font-bold">[Z]</span>
                    Estimated Horizon to CRQC (Cryptanalytically Relevant Quantum Computer)
                  </label>
                  <span className="font-mono text-amber-400 font-semibold tabular-nums">
                    {crqcHorizonZ} Years
                  </span>
                </div>
                <input
                  type="range"
                  min="3"
                  max="20"
                  value={crqcHorizonZ}
                  onChange={(e) => setCrqcHorizonZ(Number(e.target.value))}
                  className="w-full accent-amber-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  Industry consensus estimates 2029-2034 (~5 to 10 years) for fault-tolerant quantum computers capable of breaking RSA-2048.
                </p>
              </div>
            </div>
          </div>

          {/* Outcome Gauge */}
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between space-y-6">
            <div className="space-y-3">
              <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider block">
                MATHEMATICAL EVALUATION
              </span>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-center font-mono">
                <div className="text-xs text-slate-400">Formula: X + Y &gt; Z</div>
                <div className="text-lg font-bold text-white">
                  {shelfLifeX} + {migrationTimeY} ={' '}
                  <span className="text-emerald-400">{totalExposureYears} yrs</span>
                </div>
                <div className="text-xs text-slate-400">
                  vs Horizon Z:{' '}
                  <span className="text-amber-400 font-semibold">{crqcHorizonZ} yrs</span>
                </div>
              </div>

              {isBreached ? (
                <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 space-y-2">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                    <XCircle className="w-5 h-5 shrink-0" />
                    <span>DEFICIT DETECTED: {breachDeficit} YEARS</span>
                  </div>
                  <p className="text-xs text-rose-200/90 leading-relaxed">
                    Data encrypted today will still require confidentiality AFTER quantum computers emerge. Adversaries recording ciphertext today will successfully decrypt it in the future.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                    <CheckCircle2 className="w-5 h-5 shrink-0" />
                    <span>SAFE MIGRATION BUFFER: {Math.abs(breachDeficit)} YEARS</span>
                  </div>
                  <p className="text-xs text-emerald-200/90 leading-relaxed">
                    Under current estimates, you have sufficient time to migrate before CRQC deployment, provided migration starts immediately.
                  </p>
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800 text-xs text-slate-400">
              <span className="font-semibold text-slate-300">Action:</span> Initiate transition to ML-KEM-768 for TLS key exchange and ML-DSA-65 for code-signing.
            </div>
          </div>
        </div>
      )}

      {/* VIEW 3: Algorithm Threat Profiles */}
      {activeTab === 'algorithm-catalog' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {ALGORITHM_PROFILES.map((profile) => (
            <div
              key={profile.id}
              className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-white">{profile.name}</h3>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {profile.category}
                    </span>
                  </div>
                  {getRiskBadge(profile.threatSeverity)}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {profile.description}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Attack Vector:</span>
                  <span className="text-slate-200 font-semibold">{profile.quantumThreat}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Break Complexity:</span>
                  <span className="text-amber-400 font-medium truncate max-w-[180px] text-right">
                    {profile.estimatedQubitsToBreak}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>NIST Replacement:</span>
                  <span className="text-emerald-400 font-medium">
                    {profile.pqcAlternative}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
