import React from 'react';
import {
  ShieldAlert,
  BarChart3,
  Cpu,
  Lock,
  Layers,
  KeyRound,
  Radio,
  FileCode2,
  CheckCircle2,
  ChevronRight,
  PanelLeftClose,
  PanelLeftOpen,
  X,
  Server,
} from 'lucide-react';
import type { NavigationSection, RuntimeEnvironmentInfo, SecuritySubModule } from '../../types/quantum';

interface SidebarProps {
  currentSection: NavigationSection;
  onSelectSection: (section: NavigationSection) => void;
  activeSubModule: SecuritySubModule;
  onSelectSubModule: (module: SecuritySubModule) => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  criticalCount: number;
  runtime: RuntimeEnvironmentInfo | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentSection,
  onSelectSection,
  activeSubModule,
  onSelectSubModule,
  isMobileOpen,
  onCloseMobile,
  isCollapsed,
  onToggleCollapse,
  criticalCount,
  runtime,
}) => {
  const handleNavClick = (section: NavigationSection) => {
    onSelectSection(section);
    onCloseMobile();
  };

  const handleSubModuleClick = (sub: SecuritySubModule) => {
    onSelectSection('security-modules');
    onSelectSubModule(sub);
    onCloseMobile();
  };

  const navContent = (
    <div className="flex flex-col h-full bg-slate-900 border-r border-slate-800 select-none">
      {/* Brand & Collapse Controls */}
      <div className="flex items-center justify-between px-4 h-16 border-b border-slate-800">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400">
            <Lock className="w-5 h-5" />
          </div>
          {!isCollapsed && (
            <div className="truncate">
              <span className="font-semibold text-slate-100 text-sm tracking-tight block">
                QuantumShield
              </span>
              <span className="text-[11px] text-slate-400 block truncate font-mono">
                PQC Governance Suite
              </span>
            </div>
          )}
        </div>

        <button
          onClick={onCloseMobile}
          className="lg:hidden p-2 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800 transition-colors"
          aria-label="Close sidebar"
        >
          <X className="w-5 h-5" />
        </button>

        <button
          onClick={onToggleCollapse}
          className="hidden lg:flex p-1.5 text-slate-400 hover:text-slate-200 rounded-md hover:bg-slate-800 transition-colors"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
        </button>
      </div>

      {/* Live Runtime Profile */}
      {!isCollapsed && (
        <div className="px-4 py-3 mx-3 mt-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-mono text-[10px] text-slate-500">POLICY BASELINE</span>
            <span className="font-mono text-[10px] text-emerald-400 font-medium">FIPS 203/204/205</span>
          </div>
          <div className="text-xs font-medium text-slate-200 truncate font-mono">
            {runtime ? `OpenSSL ${runtime.opensslVersion}` : 'Connecting runtime...'}
          </div>
          {runtime && (
            <div className="text-[11px] text-slate-400 font-mono truncate">
              Node {runtime.nodeVersion} · {runtime.cipherCount} ciphers
            </div>
          )}
        </div>
      )}

      {/* Navigation Sections */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        <div>
          {!isCollapsed && (
            <p className="px-3 pb-2 text-[11px] font-medium text-slate-500 font-mono">
              WORKSPACE
            </p>
          )}

          <nav className="space-y-1">
            <button
              onClick={() => handleNavClick('overview')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                currentSection === 'overview'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
              title="Overview"
            >
              <div className="flex items-center gap-3 min-w-0">
                <BarChart3
                  className={`w-4 h-4 shrink-0 ${
                    currentSection === 'overview' ? 'text-emerald-400' : 'text-slate-400'
                  }`}
                />
                {!isCollapsed && <span className="truncate">Overview</span>}
              </div>
            </button>

            <button
              onClick={() => handleNavClick('risk-analysis')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                currentSection === 'risk-analysis'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
              title="Quantum Risk Analysis"
            >
              <div className="flex items-center gap-3 min-w-0">
                <ShieldAlert
                  className={`w-4 h-4 shrink-0 ${
                    currentSection === 'risk-analysis' ? 'text-amber-400' : 'text-slate-400'
                  }`}
                />
                {!isCollapsed && <span className="truncate">Quantum Risk Analysis</span>}
              </div>
              {!isCollapsed && (
                <span className="text-[11px] font-mono text-amber-400 tabular-nums shrink-0">
                  {criticalCount} critical
                </span>
              )}
            </button>

            <button
              onClick={() => handleNavClick('security-modules')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                currentSection === 'security-modules'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
              }`}
              title="Security Modules"
            >
              <div className="flex items-center gap-3 min-w-0">
                <Cpu
                  className={`w-4 h-4 shrink-0 ${
                    currentSection === 'security-modules' ? 'text-blue-400' : 'text-slate-400'
                  }`}
                />
                {!isCollapsed && <span className="truncate">Security Modules</span>}
              </div>
              {!isCollapsed && (
                <ChevronRight
                  className={`w-3.5 h-3.5 text-slate-500 transition-transform ${
                    currentSection === 'security-modules' ? 'rotate-90' : ''
                  }`}
                />
              )}
            </button>
          </nav>
        </div>

        {/* Security Sub-Modules */}
        <div className={isCollapsed ? 'space-y-1 pt-2 border-t border-slate-800' : 'space-y-1 pl-2 border-l border-slate-800 ml-3'}>
          {!isCollapsed && (
            <p className="px-3 pb-1.5 text-[11px] font-medium text-slate-500 font-mono">
              SECURITY ENGINES
            </p>
          )}

          <button
            onClick={() => handleSubModuleClick('key-generator')}
            className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-2.5 px-3'} py-2 rounded-md text-xs font-medium transition-colors ${
              currentSection === 'security-modules' && activeSubModule === 'key-generator'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
            title="PQC Key Generator"
          >
            <KeyRound className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            {!isCollapsed && <span className="truncate">PQC Key Generator</span>}
          </button>

          <button
            onClick={() => handleSubModuleClick('tls-scanner')}
            className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-2.5 px-3'} py-2 rounded-md text-xs font-medium transition-colors ${
              currentSection === 'security-modules' && activeSubModule === 'tls-scanner'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
            title="Live TLS Scanner"
          >
            <Radio className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            {!isCollapsed && <span className="truncate">Live TLS Scanner</span>}
          </button>

          <button
            onClick={() => handleSubModuleClick('cbom')}
            className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-2.5 px-3'} py-2 rounded-md text-xs font-medium transition-colors ${
              currentSection === 'security-modules' && activeSubModule === 'cbom'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
            title="Cryptographic SBOM"
          >
            <Layers className="w-3.5 h-3.5 text-purple-400 shrink-0" />
            {!isCollapsed && <span className="truncate">Cryptographic SBOM</span>}
          </button>

          <button
            onClick={() => handleSubModuleClick('policy-scanner')}
            className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-2.5 px-3'} py-2 rounded-md text-xs font-medium transition-colors ${
              currentSection === 'security-modules' && activeSubModule === 'policy-scanner'
                ? 'text-white bg-slate-800/80 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
            title="Policy & Code Scanner"
          >
            <FileCode2 className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            {!isCollapsed && <span className="truncate">Policy & Code Scanner</span>}
          </button>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800 bg-slate-900/60 text-xs">
        {!isCollapsed ? (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5 font-mono text-[11px]">
                <Server className="w-3.5 h-3.5 text-emerald-400" />
                CNSA 2.0 Target
              </span>
              <span className="font-mono text-emerald-400 text-[11px] font-medium">2030–2033</span>
            </div>
            <div className="text-[11px] text-slate-500 font-mono">
              @noble/post-quantum · CycloneDX 1.5
            </div>
          </div>
        ) : (
          <div className="flex justify-center" title="NIST FIPS 203/204/205 Engine">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      <aside
        className={`hidden lg:block shrink-0 transition-all duration-200 h-screen sticky top-0 z-30 ${
          isCollapsed ? 'w-16' : 'w-64'
        }`}
      >
        {navContent}
      </aside>

      {isMobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <div className="fixed inset-y-0 left-0 w-72 max-w-[85vw] shadow-2xl z-50">
            {navContent}
          </div>
        </div>
      )}
    </>
  );
};
