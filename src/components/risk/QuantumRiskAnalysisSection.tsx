import React, { useState } from 'react';
import { CheckCircle2, XCircle, Plus, Trash2 } from 'lucide-react';
import type { CryptoAsset, PrimitiveCategory, RiskLevel } from '../../types/quantum';
import { ALGORITHM_PROFILES } from '../../data/nistStandards';
import { calculateMoscaExposure } from '../../engine/moscaRisk';

interface QuantumRiskAnalysisProps {
  assets: CryptoAsset[];
  searchQuery: string;
  onAddAsset: (payload: {
    name: string;
    system: string;
    algorithm: string;
    keySize: number;
    primitiveType: PrimitiveCategory;
    shelfLifeYears: number;
    migrationTimeMonths: number;
    notes: string;
  }) => Promise<void>;
  onDeleteAsset: (id: string) => Promise<void>;
}

export const QuantumRiskAnalysisSection: React.FC<QuantumRiskAnalysisProps> = ({
  assets,
  searchQuery,
  onAddAsset,
  onDeleteAsset,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [activeTab, setActiveTab] = useState<'matrix' | 'mosca-calculator' | 'algorithm-catalog'>(
    'matrix'
  );
  const [showAddForm, setShowAddForm] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [newName, setNewName] = useState('');
  const [newSystem, setNewSystem] = useState('');
  const [newAlgo, setNewAlgo] = useState('RSA-2048');
  const [newKeySize, setNewKeySize] = useState<number>(2048);
  const [newPrimitive, setNewPrimitive] = useState<PrimitiveCategory>('Asymmetric');
  const [newShelfLife, setNewShelfLife] = useState<number>(10);
  const [newMigrationMonths, setNewMigrationMonths] = useState<number>(12);
  const [newNotes, setNewNotes] = useState('');

  // Mosca's Theorem Calculator States (X + Y > Z)
  const [shelfLifeX, setShelfLifeX] = useState<number>(10);
  const [migrationTimeY, setMigrationTimeY] = useState<number>(3);
  const [crqcHorizonZ, setCrqcHorizonZ] = useState<number>(7);

  const mosca = calculateMoscaExposure(shelfLifeX, migrationTimeY, crqcHorizonZ);

  const filteredAssets = assets.filter((asset) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      asset.name.toLowerCase().includes(q) ||
      asset.algorithm.toLowerCase().includes(q) ||
      asset.system.toLowerCase().includes(q);

    if (!matchesSearch) return false;
    if (selectedCategory === 'all') return true;
    if (selectedCategory === 'asymmetric') return asset.primitiveType === 'Asymmetric';
    if (selectedCategory === 'symmetric') return asset.primitiveType === 'Symmetric';
    if (selectedCategory === 'pqc')
      return asset.primitiveType === 'PQC Native' || asset.primitiveType === 'PQC Hybrid';
    return true;
  });

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!newName.trim() || !newAlgo.trim()) {
      setFormError('Asset name and algorithm are required.');
      return;
    }
    setIsSubmitting(true);
    try {
      await onAddAsset({
        name: newName.trim(),
        system: newSystem.trim() || 'Production Endpoint',
        algorithm: newAlgo.trim(),
        keySize: Number(newKeySize) || 256,
        primitiveType: newPrimitive,
        shelfLifeYears: Number(newShelfLife) || 5,
        migrationTimeMonths: Number(newMigrationMonths) || 6,
        notes: newNotes.trim() || 'Registered via Risk Matrix',
      });
      setNewName('');
      setNewSystem('');
      setNewNotes('');
      setShowAddForm(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to register asset.');
    } finally {
      setIsSubmitting(false);
    }
  };

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
        return (
          <span className="font-mono text-xs text-emerald-400 font-semibold">[COMPLIANT]</span>
        );
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
            Evaluate Shor and Grover algorithm exposure across live discovered assets and compute
            Mosca's Theorem horizons.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 self-start sm:self-auto shrink-0">
          <button
            onClick={() => setActiveTab('matrix')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeTab === 'matrix'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Asset Matrix
          </button>
          <button
            onClick={() => setActiveTab('mosca-calculator')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeTab === 'mosca-calculator'
                ? 'bg-slate-800 text-white font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Mosca's Theorem (X+Y &gt; Z)
          </button>
          <button
            onClick={() => setActiveTab('algorithm-catalog')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
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
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-400 font-mono">Filter by primitive:</span>
              <div className="flex flex-wrap items-center gap-1">
                {[
                  { id: 'all', label: 'All' },
                  { id: 'asymmetric', label: 'Asymmetric (RSA / ECC)' },
                  { id: 'symmetric', label: 'Symmetric (AES / ChaCha)' },
                  { id: 'pqc', label: 'Post-Quantum (ML-KEM / DSA)' },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setSelectedCategory(cat.id)}
                    className={`px-2.5 py-1 rounded text-xs transition-colors whitespace-nowrap ${
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

            <div className="flex items-center gap-3">
              <span className="text-slate-400 font-mono text-[11px]">
                Showing <span className="text-slate-200 font-semibold">{filteredAssets.length}</span>{' '}
                of {assets.length} primitives
              </span>
              <button
                onClick={() => setShowAddForm(!showAddForm)}
                className="px-3 py-1.5 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-xs rounded-md inline-flex items-center gap-1.5 whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Register Asset</span>
              </button>
            </div>
          </div>

          {showAddForm && (
            <form
              onSubmit={handleCreateAsset}
              className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h2 className="text-sm font-semibold text-white">
                  Register Live Cryptographic Asset for Risk Evaluation
                </h2>
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
              </div>

              {formError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
                  {formError}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div className="space-y-1">
                  <label className="text-slate-300 block">Asset Name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="e.g. Internal Root CA"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">System / Host</label>
                  <input
                    type="text"
                    value={newSystem}
                    onChange={(e) => setNewSystem(e.target.value)}
                    placeholder="e.g. Vault PKI"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Algorithm</label>
                  <input
                    type="text"
                    value={newAlgo}
                    onChange={(e) => setNewAlgo(e.target.value)}
                    placeholder="e.g. RSA-2048, AES-256, ML-KEM-768"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Primitive Category</label>
                  <select
                    value={newPrimitive}
                    onChange={(e) => setNewPrimitive(e.target.value as PrimitiveCategory)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                  >
                    <option value="Asymmetric">Asymmetric</option>
                    <option value="Symmetric">Symmetric</option>
                    <option value="Hash">Hash</option>
                    <option value="PQC Hybrid">PQC Hybrid</option>
                    <option value="PQC Native">PQC Native</option>
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Key Size (bits)</label>
                  <input
                    type="number"
                    min={64}
                    value={newKeySize}
                    onChange={(e) => setNewKeySize(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Data Shelf-Life (years)</label>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={newShelfLife}
                    onChange={(e) => setNewShelfLife(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Migration Time (months)</label>
                  <input
                    type="number"
                    min={0}
                    max={120}
                    value={newMigrationMonths}
                    onChange={(e) => setNewMigrationMonths(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300 block">Notes</label>
                  <input
                    type="text"
                    value={newNotes}
                    onChange={(e) => setNewNotes(e.target.value)}
                    placeholder="Optional compliance context"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold text-xs rounded-lg disabled:opacity-50"
                >
                  {isSubmitting ? 'Evaluating...' : 'Evaluate & Save Asset'}
                </button>
              </div>
            </form>
          )}

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
                    <th className="py-3 px-4 font-medium text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredAssets.map((asset) => (
                    <tr key={asset.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">{asset.name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          {asset.system} · {asset.source}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-mono text-slate-300 font-medium">
                          {asset.algorithm}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {asset.keySize}-bit · {asset.primitiveType}
                        </div>
                      </td>
                      <td className="py-3 px-4">{getRiskBadge(asset.quantumRisk)}</td>
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
                        <div className="text-[11px] text-slate-400 line-clamp-1">{asset.notes}</div>
                      </td>
                      <td className="py-3 px-4 text-right">
                        {(asset.source === 'manual' || asset.source === 'tls-scan') ? (
                          <button
                            onClick={() => onDeleteAsset(asset.id)}
                            className="p-1.5 text-slate-400 hover:text-rose-400 rounded transition-colors"
                            title="Remove custom asset"
                            aria-label={`Remove ${asset.name}`}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        ) : (
                          <span className="text-[11px] font-mono text-slate-500">baseline</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {filteredAssets.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-400">
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

      {/* VIEW 2: Mosca's Theorem Risk Calculator */}
      {activeTab === 'mosca-calculator' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6">
            <div>
              <h2 className="text-base font-bold text-white">
                Mosca's Theorem: Store Now, Decrypt Later (SNDL) Exposure
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Formulated by Dr. Michele Mosca: If (X + Y) &gt; Z, data encrypted today will face
                quantum decryption before the end of its required confidentiality lifetime.
              </p>
            </div>

            <div className="space-y-5">
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label htmlFor="mosca-x" className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-emerald-400 font-bold">[X]</span>
                    Data Shelf-Life (Confidentiality Requirement)
                  </label>
                  <span className="font-mono text-emerald-400 font-semibold tabular-nums">
                    {shelfLifeX} Years
                  </span>
                </div>
                <input
                  id="mosca-x"
                  type="range"
                  min="1"
                  max="30"
                  value={shelfLifeX}
                  onChange={(e) => setShelfLifeX(Number(e.target.value))}
                  className="w-full accent-emerald-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  Years that intercepted data must remain confidential (e.g., classified records,
                  health data, financial keys).
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label htmlFor="mosca-y" className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-blue-400 font-bold">[Y]</span>
                    Migration Timeframe (Deployment & Transition)
                  </label>
                  <span className="font-mono text-blue-400 font-semibold tabular-nums">
                    {migrationTimeY} Years
                  </span>
                </div>
                <input
                  id="mosca-y"
                  type="range"
                  min="1"
                  max="10"
                  value={migrationTimeY}
                  onChange={(e) => setMigrationTimeY(Number(e.target.value))}
                  className="w-full accent-blue-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  Years required to inventory, test, and deploy post-quantum algorithms across
                  production infrastructure.
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label htmlFor="mosca-z" className="text-slate-200 font-medium flex items-center gap-1.5">
                    <span className="font-mono text-amber-400 font-bold">[Z]</span>
                    Estimated Horizon to CRQC
                  </label>
                  <span className="font-mono text-amber-400 font-semibold tabular-nums">
                    {crqcHorizonZ} Years
                  </span>
                </div>
                <input
                  id="mosca-z"
                  type="range"
                  min="3"
                  max="20"
                  value={crqcHorizonZ}
                  onChange={(e) => setCrqcHorizonZ(Number(e.target.value))}
                  className="w-full accent-amber-500 bg-slate-800 h-2 rounded cursor-pointer"
                />
                <p className="text-[11px] text-slate-500">
                  Estimated years until a fault-tolerant Cryptanalytically Relevant Quantum Computer
                  can execute Shor's algorithm at scale.
                </p>
              </div>
            </div>
          </div>

          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between space-y-6">
            <div className="space-y-3">
              <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider block">
                MATHEMATICAL EVALUATION
              </span>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-center font-mono">
                <div className="text-xs text-slate-400">Mosca Inequality: X + Y &gt; Z</div>
                <div className="text-lg font-bold text-white tabular-nums">
                  {shelfLifeX} + {migrationTimeY} ={' '}
                  <span className="text-emerald-400">{mosca.totalExposureYears} yrs</span>
                </div>
                <div className="text-xs text-slate-400 tabular-nums">
                  vs Horizon Z:{' '}
                  <span className="text-amber-400 font-semibold">{crqcHorizonZ} yrs</span>
                </div>
              </div>

              {mosca.isBreached ? (
                <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 space-y-2">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                    <XCircle className="w-5 h-5 shrink-0" />
                    <span>DEFICIT DETECTED: {mosca.breachDeficitYears} YEARS</span>
                  </div>
                  <p className="text-xs text-rose-200/90 leading-relaxed">
                    Data encrypted today will still require confidentiality after CRQC emergence.
                    Adversaries harvesting ciphertext now can decrypt it within its shelf-life.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                    <CheckCircle2 className="w-5 h-5 shrink-0" />
                    <span>SAFE MIGRATION BUFFER: {Math.abs(mosca.breachDeficitYears)} YEARS</span>
                  </div>
                  <p className="text-xs text-emerald-200/90 leading-relaxed">
                    Current migration timeline completes ahead of the projected CRQC horizon,
                    provided PQC deployment begins on schedule.
                  </p>
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800 text-xs text-slate-400">
              <span className="font-semibold text-slate-300">Action:</span> Prioritize hybrid
              ML-KEM-768 key exchange for long-shelf-life data channels and ML-DSA-65/87 for code
              signing.
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

                <p className="text-xs text-slate-300 leading-relaxed">{profile.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Attack Vector:</span>
                  <span className="text-slate-200 font-semibold">{profile.quantumThreat}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Complexity:</span>
                  <span className="text-amber-400 font-medium truncate max-w-[180px] text-right">
                    {profile.estimatedQubitsToBreak}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>NIST Guidance:</span>
                  <span className="text-emerald-400 font-medium">{profile.pqcAlternative}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Reference:</span>
                  <span>{profile.reference}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
