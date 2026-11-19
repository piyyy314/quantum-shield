/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, AlertCircle } from 'lucide-react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewSection } from './components/overview/OverviewSection';
import { QuantumRiskAnalysisSection } from './components/risk/QuantumRiskAnalysisSection';
import { SecurityModulesSection } from './components/modules/SecurityModulesSection';
import type {
  AuditSummary,
  CBOMEntry,
  CryptoAsset,
  NavigationSection,
  PolicyFinding,
  PrimitiveCategory,
  RuntimeEnvironmentInfo,
  SecuritySubModule,
} from './types/quantum';
import { MIGRATION_MILESTONES } from './data/nistStandards';
import type { PqcAlgorithmId } from './engine/pqcCrypto';

export default function App() {
  const [currentSection, setCurrentSection] = useState<NavigationSection>('overview');
  const [activeSubModule, setActiveSubModule] = useState<SecuritySubModule>('key-generator');
  const [preselectedAlgorithm, setPreselectedAlgorithm] = useState<PqcAlgorithmId | undefined>(
    undefined
  );
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);

  const [cryptoAssets, setCryptoAssets] = useState<CryptoAsset[]>([]);
  const [cbomEntries, setCbomEntries] = useState<CBOMEntry[]>([]);
  const [workspaceFindings, setWorkspaceFindings] = useState<PolicyFinding[]>([]);
  const [runtime, setRuntime] = useState<RuntimeEnvironmentInfo | null>(null);
  const [lastAuditedAt, setLastAuditedAt] = useState<string | null>(null);
  const [workspaceFilesScanned, setWorkspaceFilesScanned] = useState<number>(0);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [toast, setToast] = useState<{ message: string; isError?: boolean } | null>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((message: string, isError = false) => {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
    }
    setToast({ message, isError });
    toastTimerRef.current = setTimeout(() => {
      setToast(null);
    }, 4000);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    };
  }, []);

  const runLiveAudit = useCallback(
    async (silent = false) => {
      setIsAuditing(true);
      try {
        const resp = await fetch('/api/audit', { method: 'POST' });
        if (!resp.ok) {
          throw new Error('Failed to execute live cryptographic audit.');
        }
        const data: AuditSummary = await resp.json();
        setCryptoAssets(data.assets);
        setCbomEntries(data.cbomEntries);
        setWorkspaceFindings(data.workspaceFindings);
        setRuntime(data.runtime);
        setLastAuditedAt(data.auditedAt);
        setWorkspaceFilesScanned(data.workspaceFilesScanned);

        if (!silent) {
          showToast(
            `Live audit complete: ${data.assetsDiscovered} primitives, ${data.cbomComponentsCount} CBOM components, ${data.workspaceFilesScanned} files scanned.`
          );
        }
      } catch (err) {
        if (!silent) {
          showToast(err instanceof Error ? err.message : 'Live audit failed.', true);
        }
      } finally {
        setIsAuditing(false);
        setIsLoading(false);
      }
    },
    [showToast]
  );

  useEffect(() => {
    runLiveAudit(true);
  }, [runLiveAudit]);

  const handleAddAsset = async (payload: {
    name: string;
    system: string;
    algorithm: string;
    keySize: number;
    primitiveType: PrimitiveCategory;
    shelfLifeYears: number;
    migrationTimeMonths: number;
    notes: string;
  }) => {
    const resp = await fetch('/api/inventory', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'Failed to register asset.');
    }
    await runLiveAudit(true);
    showToast(`Registered ${data.name} (${data.quantumRisk}).`);
  };

  const handleDeleteAsset = async (id: string) => {
    const resp = await fetch(`/api/inventory/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (resp.ok) {
      await runLiveAudit(true);
      showToast('Asset removed from live inventory.');
    }
  };

  const handleExportReport = () => {
    const reportData = {
      title: 'QuantumShield Post-Quantum Cryptography Live Audit Report',
      auditTimestamp: lastAuditedAt ?? new Date().toISOString(),
      runtimeEnvironment: runtime,
      standardsReferenced: [
        'NIST FIPS 203 (ML-KEM)',
        'NIST FIPS 204 (ML-DSA)',
        'NIST FIPS 205 (SLH-DSA)',
        'NSA CNSA 2.0',
        'OMB M-23-02 / NSM-10',
      ],
      totalPrimitivesAudited: cryptoAssets.length,
      criticalRisksIdentified: cryptoAssets.filter((a) => a.quantumRisk === 'CRITICAL').length,
      cbomComponentsCount: cbomEntries.length,
      workspaceFindingsCount: workspaceFindings.length,
      assets: cryptoAssets,
      cbom: cbomEntries,
      workspaceFindings,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `quantumshield_live_audit_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast('Live cryptographic posture report exported as JSON.');
  };

  const criticalCount = cryptoAssets.filter((a) => a.quantumRisk === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {toast && (
        <div
          className={`fixed bottom-5 right-5 z-50 p-4 rounded-xl bg-slate-900 border shadow-2xl text-xs text-slate-100 flex items-center gap-3 ${
            toast.isError ? 'border-rose-500/40' : 'border-emerald-500/40'
          }`}
        >
          {toast.isError ? (
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      <div className="flex-1 flex w-full">
        <Sidebar
          currentSection={currentSection}
          onSelectSection={(sec) => setCurrentSection(sec)}
          activeSubModule={activeSubModule}
          onSelectSubModule={(sub) => setActiveSubModule(sub)}
          isMobileOpen={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
          criticalCount={criticalCount}
          runtime={runtime}
        />

        <div className="flex-1 flex flex-col min-w-0">
          <Header
            currentSection={currentSection}
            onOpenMobileSidebar={() => setIsMobileSidebarOpen(true)}
            onRunAudit={() => runLiveAudit(false)}
            isAuditing={isAuditing}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            onExportReport={handleExportReport}
          />

          <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
            {currentSection === 'overview' && (
              <OverviewSection
                assets={cryptoAssets}
                milestones={MIGRATION_MILESTONES}
                runtime={runtime}
                lastAuditedAt={lastAuditedAt}
                workspaceFilesScanned={workspaceFilesScanned}
                cbomCount={cbomEntries.length}
                isLoading={isLoading}
                searchQuery={searchQuery}
                onNavigateSection={setCurrentSection}
                onNavigateSubModule={(sub, preselect) => {
                  if (preselect) setPreselectedAlgorithm(preselect);
                  setCurrentSection('security-modules');
                  setActiveSubModule(sub);
                }}
              />
            )}

            {currentSection === 'risk-analysis' && (
              <QuantumRiskAnalysisSection
                assets={cryptoAssets}
                searchQuery={searchQuery}
                onAddAsset={handleAddAsset}
                onDeleteAsset={handleDeleteAsset}
              />
            )}

            {currentSection === 'security-modules' && (
              <SecurityModulesSection
                activeSubModule={activeSubModule}
                onSelectSubModule={setActiveSubModule}
                preselectedAlgorithm={preselectedAlgorithm}
                cbomEntries={cbomEntries}
                onUpdateCbomEntries={setCbomEntries}
                workspaceFindings={workspaceFindings}
                searchQuery={searchQuery}
                onTlsAssetRecorded={() => runLiveAudit(true)}
              />
            )}
          </main>
        </div>
      </div>
    </div>
  );
}
