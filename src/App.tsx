/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewSection } from './components/overview/OverviewSection';
import { QuantumRiskAnalysisSection } from './components/risk/QuantumRiskAnalysisSection';
import { SecurityModulesSection } from './components/modules/SecurityModulesSection';
import { NavigationSection, SecuritySubModule, CryptoAsset } from './types/quantum';
import { INITIAL_CRYPTO_ASSETS, MIGRATION_MILESTONES } from './data/mockQuantumData';
import { CheckCircle2 } from 'lucide-react';

export default function App() {
  const [currentSection, setCurrentSection] = useState<NavigationSection>('overview');
  const [activeSubModule, setActiveSubModule] = useState<SecuritySubModule>('key-generator');
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  
  const [cryptoAssets, setCryptoAssets] = useState<CryptoAsset[]>(INITIAL_CRYPTO_ASSETS);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  // Run simulated cryptographic audit
  const handleRunAudit = () => {
    setIsAuditing(true);
    setTimeout(() => {
      setIsAuditing(false);
      showToast('Quantum cryptographic audit completed. All 8 primitives verified against FIPS 203/204.');
    }, 1200);
  };

  // Export full JSON report
  const handleExportReport = () => {
    const reportData = {
      title: 'Enterprise Post-Quantum Cryptography Audit Report',
      auditTimestamp: new Date().toISOString(),
      standardsReferenced: ['NIST FIPS 203 (ML-KEM)', 'NIST FIPS 204 (ML-DSA)', 'NIST FIPS 205 (SLH-DSA)', 'NSA CNSA 2.0'],
      totalPrimitivesAudited: cryptoAssets.length,
      criticalRisksIdentified: cryptoAssets.filter(a => a.quantumRisk === 'CRITICAL').length,
      assets: cryptoAssets,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `quantum_security_audit_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast('Cryptographic posture report downloaded as JSON.');
  };

  const criticalCount = cryptoAssets.filter((a) => a.quantumRisk === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 p-4 rounded-xl bg-slate-900 border border-emerald-500/40 shadow-2xl text-xs text-slate-100 flex items-center gap-3 animate-in fade-in slide-in-from-bottom-2 duration-200">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      <div className="flex-1 flex w-full">
        {/* Responsive Sidebar */}
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
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0">
          <Header
            currentSection={currentSection}
            onOpenMobileSidebar={() => setIsMobileSidebarOpen(true)}
            onRunAudit={handleRunAudit}
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
                onNavigateSection={setCurrentSection}
                onNavigateSubModule={(sub) => {
                  setCurrentSection('security-modules');
                  setActiveSubModule(sub);
                }}
              />
            )}

            {currentSection === 'risk-analysis' && (
              <QuantumRiskAnalysisSection
                assets={cryptoAssets}
                searchQuery={searchQuery}
              />
            )}

            {currentSection === 'security-modules' && (
              <SecurityModulesSection
                activeSubModule={activeSubModule}
                onSelectSubModule={setActiveSubModule}
              />
            )}
          </main>
        </div>
      </div>
    </div>
  );
}
