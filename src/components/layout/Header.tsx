import React from 'react';
import { Menu, Search, RefreshCw, Download, ShieldCheck } from 'lucide-react';
import { NavigationSection } from '../../types/quantum';

interface HeaderProps {
  currentSection: NavigationSection;
  onOpenMobileSidebar: () => void;
  onRunAudit: () => void;
  isAuditing: boolean;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onExportReport: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentSection,
  onOpenMobileSidebar,
  onRunAudit,
  isAuditing,
  searchQuery,
  onSearchChange,
  onExportReport,
}) => {
  const getSectionTitle = () => {
    switch (currentSection) {
      case 'overview':
        return 'Executive Overview';
      case 'risk-analysis':
        return 'Quantum Risk Analysis';
      case 'security-modules':
        return 'Security Modules';
      default:
        return 'Workspace';
    }
  };

  return (
    <header className="h-16 px-4 sm:px-6 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 flex items-center justify-between sticky top-0 z-20">
      {/* Zone 1: Mobile Hamburger & Contextual Breadcrumb */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onOpenMobileSidebar}
          className="lg:hidden p-2 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
          aria-label="Open sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>

        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs truncate">
          <span className="text-slate-400 font-medium">Enterprise Security</span>
          <span className="text-slate-600 font-mono">/</span>
          <span className="text-slate-100 font-semibold truncate">{getSectionTitle()}</span>
        </nav>
      </div>

      {/* Zone 2: Global Search */}
      <div className="hidden md:flex items-center flex-1 max-w-md mx-6">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search cryptographic assets, algorithms (e.g. RSA, Kyber)..."
            className="w-full bg-slate-950/70 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs font-mono"
            >
              esc
            </button>
          )}
        </div>
      </div>

      {/* Zone 3: Primary Actions */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        <button
          onClick={onRunAudit}
          disabled={isAuditing}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700/80 rounded-lg border border-slate-700 transition-colors disabled:opacity-50 whitespace-nowrap"
          title="Run cryptographic posture audit"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${isAuditing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">{isAuditing ? 'Auditing...' : 'Run Audit'}</span>
        </button>

        <button
          onClick={onExportReport}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-slate-900 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors whitespace-nowrap"
          title="Export Cryptographic Inventory & Risk Report"
        >
          <Download className="w-3.5 h-3.5" />
          <span className="font-semibold">Export Report</span>
        </button>

        <div className="hidden xl:flex items-center gap-2 pl-3 border-l border-slate-800 text-xs text-slate-400 font-mono">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>CNSA 2.0</span>
        </div>
      </div>
    </header>
  );
};
