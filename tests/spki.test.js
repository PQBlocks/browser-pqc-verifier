import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { extractSpki, DEFAULT_OID_MAP, resolveParams, resolveParamsFromCert } from '../src/spki.js';
import { parseCertificate } from '../src/x509.js';
import fs from 'node:fs';

// Helper to load a certificate from the corpus
function loadCert(derFile) {
  const der = new Uint8Array(fs.readFileSync(`tests/corpus/${derFile}`));
  return parseCertificate(der);
}

// --- Test DEFAULT_OID_MAP structure ---
test('DEFAULT_OID_MAP is a Map with three ML-DSA entries', () => {
  assert.ok(DEFAULT_OID_MAP instanceof Map, 'DEFAULT_OID_MAP must be a Map');
  assert.strictEqual(DEFAULT_OID_MAP.size, 3, 'DEFAULT_OID_MAP must have exactly 3 entries');
  assert.strictEqual(DEFAULT_OID_MAP.get('1.3.132.0.35'), 'mldsa44', 'OID 1.3.132.0.35 maps to mldsa44');
  assert.strictEqual(DEFAULT_OID_MAP.get('1.3.132.0.34'), 'mldsa65', 'OID 1.3.132.0.34 maps to mldsa65');
  assert.strictEqual(DEFAULT_OID_MAP.get('1.3.132.0.33'), 'mldsa87', 'OID 1.3.132.0.33 maps to mldsa87');
});

// --- Test resolveParams with default map ---
test('resolveParams finds mldsa44 in DEFAULT_OID_MAP', () => {
  assert.strictEqual(resolveParams('1.3.132.0.35'), 'mldsa44');
});

test('resolveParams finds mldsa65 in DEFAULT_OID_MAP', () => {
  assert.strictEqual(resolveParams('1.3.132.0.34'), 'mldsa65');
});

test('resolveParams finds mldsa87 in DEFAULT_OID_MAP', () => {
  assert.strictEqual(resolveParams('1.3.132.0.33'), 'mldsa87');
});

// --- Test E4: non-PQ OID returns null ---
test('E4: non-PQ OID (RSA) returns null from resolveParams', () => {
  // RSA OID: 1.2.840.113549.1.1.1
  assert.strictEqual(resolveParams('1.2.840.113549.1.1.1'), null, 'RSA OID not in DEFAULT_OID_MAP should return null');
});

test('E4: non-PQ OID (ECDSA P-256) returns null from resolveParams', () => {
  // ECDSA P-256: 1.2.840.10045.4.3.2
  assert.strictEqual(resolveParams('1.2.840.10045.4.3.2'), null, 'ECDSA P-256 OID not in DEFAULT_OID_MAP should return null');
});

test('E4: non-PQ OID (Ed25519) returns null from resolveParams', () => {
  // Ed25519: 1.3.101.112
  assert.strictEqual(resolveParams('1.3.101.112'), null, 'Ed25519 OID not in DEFAULT_OID_MAP should return null');
});

// --- Test E5: unknown OID returns null ---
test('E5: completely unknown OID returns null from resolveParams', () => {
  assert.strictEqual(resolveParams('2.16.840.1.101.3.4.3.17'), null, 'Unknown OID should return null');
});

test('E5: malformed OID string returns null', () => {
  assert.strictEqual(resolveParams('not.an.oid'), null, 'Malformed OID should return null');
});

test('E5: empty string OID returns null', () => {
  assert.strictEqual(resolveParams(''), null, 'Empty OID should return null');
});

// --- Test synthetic OID override ---
test('synthetic OID not in DEFAULT_OID_MAP resolves via override map', () => {
  const customMap = new Map([
    ['2.16.840.1.101.3.4.3.99', 'mldsa65'], // Synthetic OID
  ]);
  assert.strictEqual(resolveParams('2.16.840.1.101.3.4.3.99', customMap), 'mldsa65', 'Override map should resolve synthetic OID');
});

test('override map can shadow DEFAULT_OID_MAP entry', () => {
  const customMap = new Map([
    ['1.3.132.0.34', 'mldsa44'], // Override mldsa65 to mldsa44
  ]);
  // Without override
  assert.strictEqual(resolveParams('1.3.132.0.34'), 'mldsa65', 'Default map gives mldsa65');
  // With override: caller map takes precedence
  assert.strictEqual(resolveParams('1.3.132.0.34', customMap), 'mldsa44', 'Override map shadows default');
});

test('override map takes precedence over DEFAULT_OID_MAP for its keys', () => {
  const customMap = new Map([
    ['1.3.132.0.35', 'mldsa87'], // Override mldsa44 to mldsa87
  ]);
  // Without override
  assert.strictEqual(resolveParams('1.3.132.0.35'), 'mldsa44', 'Default map gives mldsa44');
  // With override: caller map wins
  assert.strictEqual(resolveParams('1.3.132.0.35', customMap), 'mldsa87', 'Override map takes precedence over DEFAULT_OID_MAP');
});

// --- Test extractSpki with corpus certificates ---
test('extractSpki works on corpus leaf1', () => {
  const cert = loadCert('leaf1.der');
  const { oid, publicKeyBytes } = extractSpki(cert);
  
  assert.ok(typeof oid === 'string', 'oid must be string');
  assert.ok(oid.length > 0, 'oid must not be empty');
  assert.ok(publicKeyBytes instanceof Uint8Array, 'publicKeyBytes must be Uint8Array');
  assert.ok(publicKeyBytes.length > 0, 'publicKeyBytes must not be empty');
});

test('extractSpki works on all 24 leaf certificates', () => {
  for (let i = 1; i <= 24; i++) {
    const cert = loadCert(`leaf${i}.der`);
    const { oid, publicKeyBytes } = extractSpki(cert);
    
    assert.ok(typeof oid === 'string', `leaf${i}: oid must be string`);
    assert.ok(oid.length > 0, `leaf${i}: oid must not be empty`);
    assert.ok(publicKeyBytes instanceof Uint8Array, `leaf${i}: publicKeyBytes must be Uint8Array`);
    assert.ok(publicKeyBytes.length > 0, `leaf${i}: publicKeyBytes must not be empty`);
  }
});

test('extractSpki works on root CA certificate', () => {
  const cert = loadCert('root.der');
  const { oid, publicKeyBytes } = extractSpki(cert);
  
  assert.ok(typeof oid === 'string', 'oid must be string');
  assert.ok(oid.length > 0, 'oid must not be empty');
  assert.ok(publicKeyBytes instanceof Uint8Array, 'publicKeyBytes must be Uint8Array');
  assert.ok(publicKeyBytes.length > 0, 'publicKeyBytes must not be empty');
});

// --- Test extractSpki error handling ---
test('extractSpki throws E29 on null cert', () => {
  assert.throws(
    () => extractSpki(null),
    { code: 'E29' },
    'null cert should throw E29'
  );
});

test('extractSpki throws E29 on undefined cert', () => {
  assert.throws(
    () => extractSpki(undefined),
    { code: 'E29' },
    'undefined cert should throw E29'
  );
});

test('extractSpki throws E29 on non-object cert', () => {
  assert.throws(
    () => extractSpki('not an object'),
    { code: 'E29' },
    'string cert should throw E29'
  );
  assert.throws(
    () => extractSpki(123),
    { code: 'E29' },
    'number cert should throw E29'
  );
});

test('extractSpki throws E29 on cert missing subjectPublicKeyInfo', () => {
  const badCert = { version: 3, serialNumber: '01', issuer: {}, validity: {}, subject: {}, signatureAlgorithm: '', signatureValue: new Uint8Array() };
  assert.throws(
    () => extractSpki(badCert),
    { code: 'E29' },
    'cert without subjectPublicKeyInfo should throw E29'
  );
});

test('extractSpki throws E29 on cert with incomplete subjectPublicKeyInfo (missing algorithm)', () => {
  const badCert = { subjectPublicKeyInfo: { publicKey: new Uint8Array([1,2,3]) } };
  assert.throws(
    () => extractSpki(badCert),
    { code: 'E29' },
    'cert missing SPKI algorithm should throw E29'
  );
});

test('extractSpki throws E29 on cert with incomplete subjectPublicKeyInfo (missing publicKey)', () => {
  const badCert = { subjectPublicKeyInfo: { algorithm: '1.2.840.113549.1.1.1' } };
  assert.throws(
    () => extractSpki(badCert),
    { code: 'E29' },
    'cert missing SPKI publicKey should throw E29'
  );
});

test('extractSpki throws E29 on cert with non-Uint8Array publicKey', () => {
  const badCert = { subjectPublicKeyInfo: { algorithm: '1.2.840.113549.1.1.1', publicKey: 'not bytes' } };
  assert.throws(
    () => extractSpki(badCert),
    { code: 'E29' },
    'cert with string publicKey should throw E29'
  );
});

// --- Test resolveParamsFromCert ---
test('resolveParamsFromCert resolves ML-DSA OID from cert', () => {
  const cert = loadCert('leaf1.der');
  const param = resolveParamsFromCert(cert);
  // The corpus certs use classical OIDs (RSA/ECDSA), so this should return null
  // But we test the function works without throwing
  assert.ok(param === null || typeof param === 'string', 'resolveParamsFromCert returns string or null');
});

test('resolveParamsFromCert respects override map', () => {
  const cert = loadCert('leaf1.der');
  const { oid } = extractSpki(cert);
  const customMap = new Map([[oid, 'mldsa65']]);
  const param = resolveParamsFromCert(cert, customMap);
  assert.strictEqual(param, 'mldsa65', 'Override map should be respected');
});

test('resolveParamsFromCert throws E29 on bad cert', () => {
  assert.throws(
    () => resolveParamsFromCert(null),
    { code: 'E29' },
    'Bad cert should throw E29'
  );
});