// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { OverviewSection } from '../src/components/overview/OverviewSection.tsx';
import { QuantumRiskAnalysisSection } from '../src/components/risk/QuantumRiskAnalysisSection.tsx';
import { MIGRATION_MILESTONES } from '../src/data/nistStandards.ts';

describe('QuantumShield React UI Components', () => {
  it('renders OverviewSection cleanly with zero assets without NaN percentages', () => {
    render(
      <OverviewSection
        assets={[]}
        milestones={MIGRATION_MILESTONES}
        runtime={null}
        lastAuditedAt={null}
        workspaceFilesScanned={12}
        cbomCount={3}
        isLoading={false}
        searchQuery=""
        onNavigateSection={vi.fn()}
        onNavigateSubModule={vi.fn()}
      />
    );

    expect(screen.getByText('Post-Quantum Cryptography & Risk Posture')).toBeInTheDocument();
    expect(screen.getAllByText('0%').length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText('NaN%')).not.toBeInTheDocument();
  });

  it("renders Mosca's Theorem Calculator and updates evaluation dynamically", () => {
    render(
      <QuantumRiskAnalysisSection
        assets={[]}
        searchQuery=""
        onAddAsset={vi.fn()}
        onDeleteAsset={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /Mosca's Theorem/i }));
    expect(screen.getByText(/DEFICIT DETECTED: 6 YEARS/i)).toBeInTheDocument();

    const zSlider = screen.getByLabelText(/Estimated Horizon to CRQC/i);
    fireEvent.change(zSlider, { target: { value: '18' } });
    expect(screen.getByText(/SAFE MIGRATION BUFFER: 5 YEARS/i)).toBeInTheDocument();
  });
});
