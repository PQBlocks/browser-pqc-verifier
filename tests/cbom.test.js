import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCertificate } from '../src/x509.js';
import { extractSpki, DEFAULT_OID_MAP } from '../src/spki.js';
import { generateCbom, CBOM_SCHEMA_VERSION } from '../src/cbom.js';

// ============================================================================
// CBOM emitter — ground truth + determinism + E20 (no shared state)
// ============================================================================
//
// Tests (contract from specification):
//   1. generateCbom on the 25-cert corpus produces deterministic output
//   2. matches the checked-in CBOM ground truth 25/25
//   3. E20: no shared state between calls (same inputs => identical output,
//      and an interleaved second call does not mutate the first result)
//   4. schema version is 'cbom-1.0'; no timestamps present in v1
//   5. contract: algorithm inventory derived from cert SPKIs exactly
//
// RED first: this file runs against a not-yet-existing src/cbom.js.

const fs = { readFileSync };

// Load corpus and parse all 25 certs once
const manifest = JSON.parse(fs.readFileSync('tests/corpus/manifest.json', 'utf8'));
const certFiles = Object.keys(manifest).sort();
const allCerts = certFiles.map(fname => {
  const der = new Uint8Array(fs.readFileSync('tests/corpus/' + fname));
  return parseCertificate(der);
});

// Load ground truth
const groundTruth = JSON.parse(fs.readFileSync('tests/corpus/cbom-groundtruth.json', 'utf8'));

describe('S8 CBOM emitter', () => {
  test('T1: generateCbom exists and exports a stable schema version', () => {
    assert.strictEqual(typeof generateCbom, 'function', 'generateCbom must be a function');
    assert.strictEqual(CBOM_SCHEMA_VERSION, 'cbom-1.0', 'schema version constant must be cbom-1.0');
  });

  test('T2: ground-truth match 25/25 on corpus', () => {
    const result = generateCbom(allCerts);
    // Deep equal on all fields
    assert.deepStrictEqual(result, groundTruth, 'CBOM output must match ground truth exactly');
  });

  test('T3: deterministic for identical input', () => {
    const r1 = generateCbom(allCerts);
    const r2 = generateCbom(allCerts);
    // Must be identical, not just equal
    assert.deepStrictEqual(r1, r2, 'identical input must produce identical output');
    // And not the same object reference (no mutation of cached state)
    assert.notStrictEqual(r1, r2, 'must return new object each call');
  });

  test('T4: E20 - no shared state between calls (interleaved)', () => {
    // Interleaved calls must not mutate each other's results
    const r1 = generateCbom(allCerts);
    const r2 = generateCbom(allCerts.filter((_, i) => i < 5)); // subset
    const r3 = generateCbom(allCerts);
    // r1 and r3 must be identical (full corpus)
    assert.deepStrictEqual(r1, r3, 'interleaved call must not affect prior full-corpus result');
    // r2 must be different (fewer certs)
    assert.notDeepStrictEqual(r1, r2, 'subset must produce different result');
  });

  test('T5: E19/negative - bad inputs throw typed errors', () => {
    // Not an array
    assert.throws(() => generateCbom(null), { name: 'Error', code: 'E20' });
    assert.throws(() => generateCbom(undefined), { name: 'Error', code: 'E20' });
    assert.throws(() => generateCbom('not an array'), { name: 'Error', code: 'E20' });
    assert.throws(() => generateCbom(123), { name: 'Error', code: 'E20' });
    
    // Array with non-object elements
    assert.throws(() => generateCbom([null]), { name: 'Error', code: 'E20' });
    assert.throws(() => generateCbom([{}]), { name: 'Error', code: 'E20' }); // missing spki
    assert.throws(() => generateCbom([{ spki: null }]), { name: 'Error', code: 'E20' });
  });

  test('T6: empty array returns valid empty CBOM', () => {
    const result = generateCbom([]);
    assert.deepStrictEqual(result, {
      schema: 'cbom-1.0',
      algorithms: [],
      keySizes: [],
      certCount: 0
    });
  });

  test('T7: algorithms derived from SPKI OIDs via extractSpki/resolveParams', () => {
    // This test documents the expected mapping behavior
    // For ML-DSA OIDs, resolve to mldsa44/65/87
    // For unknown OIDs, emit the raw OID string
    const mockCerts = [
      { spki: { oid: '1.3.132.0.34', publicKey: new Uint8Array(1952) } }, // ML-DSA-65
      { spki: { oid: '1.3.132.0.35', publicKey: new Uint8Array(1312) } }, // ML-DSA-44
      { spki: { oid: '1.2.840.113549.1.1.1', publicKey: new Uint8Array(270) } }, // RSA
    ];
    const result = generateCbom(mockCerts);
    assert.deepStrictEqual(result.algorithms.sort(), ['1.2.840.113549.1.1.1', 'mldsa44', 'mldsa65']);
    assert.deepStrictEqual(result.keySizes.sort((a,b)=>a-b), [270, 1312, 1952]);
    assert.strictEqual(result.certCount, 3);
    assert.strictEqual(result.schema, 'cbom-1.0');
  });
});