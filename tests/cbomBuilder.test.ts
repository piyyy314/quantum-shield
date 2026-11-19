import { describe, it, expect } from 'vitest';
import {
  buildCycloneDxCbom,
  parsePackageJsonManifest,
  parseTextManifest,
} from '../src/engine/cbomBuilder.ts';

describe('CBOM Manifest Parser & CycloneDX 1.5 Builder', () => {
  it('parses package.json cryptographic dependencies and excludes unrelated packages', () => {
    const pkg = JSON.stringify({
      dependencies: {
        '@noble/post-quantum': '^0.7.1',
        'node-forge': '^1.3.1',
        'lodash': '^4.17.21',
      },
    });

    const entries = parsePackageJsonManifest(pkg);
    expect(entries).toHaveLength(2);
    expect(entries.find((e) => e.component === '@noble/post-quantum')?.riskLevel).toBe('COMPLIANT');
    expect(entries.find((e) => e.component === 'node-forge')?.riskLevel).toBe('CRITICAL');
  });

  it('parses Python requirements.txt and Go go.mod manifests', () => {
    const py = parseTextManifest('cryptography==42.0.5\nrequests==2.32.0', 'requirements.txt');
    expect(py).toHaveLength(1);
    expect(py[0].component).toBe('cryptography');

    const go = parseTextManifest('require golang.org/x/crypto v0.24.0', 'go.mod');
    expect(go).toHaveLength(1);
    expect(go[0].version).toBe('v0.24.0');
  });

  it('builds a valid CycloneDX 1.5 CBOM JSON document', () => {
    const entries = parsePackageJsonManifest(
      JSON.stringify({ dependencies: { '@noble/post-quantum': '^0.7.1' } })
    );
    const bom = buildCycloneDxCbom(entries, 'QuantumShield', '1.0.0');

    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    expect(bom.serialNumber).toMatch(/^urn:uuid:/);
    expect(bom.components).toHaveLength(1);
    expect(bom.components[0].cryptoProperties.assetType).toBe('algorithm');
  });
});
