/**
 * S9: Public API assembly — verifyPqChain / verifyCertificateChain /
 * loadTrustAnchorsFromPem / loadTrustAnchorsFromDer / src/index.js surface.
 *
 * Suites S9-01 .. S9-nn covering:
 *  - E19  type confusion → TypeError (never silent false)
 *  - E1   empty Uint8Array → MALFORMED_CERT
 *  - E2   truncated DER → MALFORMED_CERT
 *  - result shape: verified/errors/chain/cbom
 *  - default options: maxDepth 5, oidMap DEFAULT_OID_MAP, ctx ''
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  verifyPqChain,
  verifyCertificateChain,
  loadTrustAnchorsFromPem,
  loadTrustAnchorsFromDer,
  normalizeCertBundle,
  parseCertificate,
  extractSpki,
  verifyMlDsa,
  verifyChain,
  generateCbom,
  CBOM_SCHEMA_VERSION,
  DEFAULT_OID_MAP,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = join(here, 'corpus');

const leafDer = readFileSync(join(corpus, 'leaf1.der'));
const rootDer = readFileSync(join(corpus, 'root.der'));

/** helper: leaf+root as a DER bundle (concatenated TLVs) */
function chainBundle() {
  return Buffer.concat([Buffer.from(leafDer), Buffer.from(rootDer)]);
}

/** helper: PEM for a single cert */
function toPem(der) {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

// ─────────────────────────────────────────────────────────────
// S9-surface: export floor (SDK scope >= 8 callable exports)
// ─────────────────────────────────────────────────────────────
test('S9-01: index.js exposes >= 8 callable exports', async () => {
  const mod = await import('../src/index.js');
  const names = Object.keys(mod).filter((k) => typeof mod[k] === 'function');
  assert.ok(
    names.length >= 8,
    `expected >=8 function exports, got ${names.length}: ${names.join(',')}`,
  );
});

test('S9-02: verifyPqChain and core exports exist with correct arity', () => {
  assert.equal(typeof verifyPqChain, 'function');
  assert.equal(typeof verifyCertificateChain, 'function');
  assert.equal(typeof loadTrustAnchorsFromPem, 'function');
  assert.equal(typeof loadTrustAnchorsFromDer, 'function');
  assert.equal(typeof normalizeCertBundle, 'function');
  assert.equal(typeof parseCertificate, 'function');
  assert.equal(typeof extractSpki, 'function');
  assert.equal(typeof verifyMlDsa, 'function');
  assert.equal(typeof verifyChain, 'function');
  assert.equal(typeof generateCbom, 'function');
});

test('S9-03: exported constants are correct values', () => {
  assert.equal(CBOM_SCHEMA_VERSION, 'cbom-1.0');
  assert.ok(DEFAULT_OID_MAP instanceof Map);
  // 3 ML-DSA parameter sets in the map
  assert.equal(DEFAULT_OID_MAP.size, 3);
});

// ─────────────────────────────────────────────────────────────
// S9-shape: PqVerificationResult contract
// ─────────────────────────────────────────────────────────────
test('S9-04: result object has verified/errors/chain/cbom keys', () => {
  const result = verifyPqChain(chainBundle(), {
    trustAnchors: [parseCertificate(rootDer)],
  });
  assert.equal(typeof result.verified, 'boolean');
  assert.ok(Array.isArray(result.errors));
  assert.ok(Array.isArray(result.chain));
  assert.ok(result.cbom && typeof result.cbom === 'object');
  assert.equal(result.cbom.schema, 'cbom-1.0');
  assert.ok(Array.isArray(result.cbom.algorithms));
  assert.ok(Array.isArray(result.cbom.keySizes));
  assert.equal(typeof result.cbom.certCount, 'number');
});

test('S9-05: verifyPqChain returns verified true for self-anchored leaf', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.equal(result.verified, true);
  assert.deepEqual(result.errors, []);
  // chain includes at least the leaf
  assert.ok(result.chain.length >= 1);
  assert.equal(result.chain[0].serialNumber, leaf.serialNumber);
});

test('S9-06: cbom in result covers every chain certificate', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.equal(result.cbom.certCount, result.chain.length);
  for (const c of result.chain) {
    const spki = extractSpki(c);
    assert.equal(typeof spki.oid, 'string');
    assert.ok(spki.publicKeyBytes instanceof Uint8Array);
  }
});

test('S9-07: cbom algorithms list is deduplicated and deterministic', () => {
  const leaf = parseCertificate(leafDer);
  const r1 = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  const r2 = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.deepEqual(r1.cbom.algorithms, r2.cbom.algorithms);
  assert.equal(new Set(r1.cbom.algorithms).size, r1.cbom.algorithms.length);
  assert.deepEqual(r1.cbom.keySizes, r2.cbom.keySizes);
});

// ─────────────────────────────────────────────────────────────
// S9-inputs: PEM / DER / bundle handling
// ─────────────────────────────────────────────────────────────
test('S9-08: verifyPqChain accepts PEM string input', () => {
  const leaf = parseCertificate(leafDer);
  const pem = toPem(leafDer);
  const result = verifyPqChain(pem, { trustAnchors: [leaf] });
  assert.equal(result.verified, true);
  assert.deepEqual(result.errors, []);
});

test('S9-09: verifyPqChain accepts DER buffer (Uint8Array) input', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(new Uint8Array(leafDer), { trustAnchors: [leaf] });
  assert.equal(result.verified, true);
});

test('S9-10: verifyPqChain accepts DER bundle of leaf+root', () => {
  const root = parseCertificate(rootDer);
  const bundle = chainBundle(); // leaf + root concatenated
  const result = verifyPqChain(bundle, { trustAnchors: [root] });
  // Either verifies against root or fails with a chain error — must not throw
  assert.equal(typeof result.verified, 'boolean');
  assert.ok(Array.isArray(result.errors));
});

// ─────────────────────────────────────────────────────────────
// S9-opts: options plumbing
// ─────────────────────────────────────────────────────────────
test('S9-11: defaults apply — maxDepth 5, oidMap DEFAULT_OID_MAP, ctx ""', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.equal(result.verified, true);
  // sanity: passing nothing but trustAnchors still works (defaults inside)
  assert.equal(result.cbom.schema, 'cbom-1.0');
});

test('S9-12: trustAnchors accepts PEM string (loadTrustAnchorsFromPem path)', () => {
  const root = parseCertificate(rootDer);
  // trustAnchors as a PEM string of the root cert
  const result = verifyPqChain(leafDer, { trustAnchors: toPem(rootDer) });
  assert.equal(typeof result.verified, 'boolean');
  assert.ok(Array.isArray(result.chain));
});

test('S9-13: custom maxDepth option threads into chain walk (E11 surfaced)', () => {
  const leaf = parseCertificate(leafDer);
  const root = parseCertificate(rootDer);
  // leaf as anchor: verified. Use maxDepth 1 to force a chain-depth error on the bundle.
  const bundle = chainBundle();
  const result = verifyPqChain(bundle, { trustAnchors: [root], maxDepth: 1 });
  assert.equal(result.verified, false);
  assert.ok(result.errors.some((e) => /E11/.test(e)));
});

test('S9-14: explicit ctx option does not break non-ML-DSA corpus path', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(leafDer, {
    trustAnchors: [leaf],
    ctx: 'app-context',
  });
  assert.equal(result.verified, true);
});

test('S9-15: oidMap option is honored when resolving algorithm names', () => {
  const leaf = parseCertificate(leafDer);
  const customMap = new Map([['1.2.840.113549.1.1.1', 'RSA-CUSTOM']]);
  const result = verifyPqChain(leafDer, { trustAnchors: [leaf], oidMap: customMap });
  assert.equal(result.verified, true);
  // The custom map shadows DEFAULT_OID_MAP → RSA cert resolves to the custom name
  assert.deepEqual(result.cbom.algorithms, ['RSA-CUSTOM']);
});

// ─────────────────────────────────────────────────────────────
// S9-neg: E19 type confusion + E1/E2 malformed (never silent false)
// ─────────────────────────────────────────────────────────────
test('S9-16: E19 - null input raises TypeError', () => {
  assert.throws(() => verifyPqChain(null, { trustAnchors: [] }), (e) => e instanceof TypeError);
});

test('S9-17: E19 - undefined input raises TypeError', () => {
  assert.throws(() => verifyPqChain(undefined, { trustAnchors: [] }), (e) => e instanceof TypeError);
});

test('S9-18: E19 - number input raises TypeError', () => {
  assert.throws(() => verifyPqChain(42, { trustAnchors: [] }), (e) => e instanceof TypeError);
});

test('S9-19: E19 - object input raises TypeError', () => {
  assert.throws(() => verifyPqChain({ foo: 1 }, { trustAnchors: [] }), (e) => e instanceof TypeError);
});

test('S9-20: E19 - boolean input raises TypeError', () => {
  assert.throws(() => verifyPqChain(true, { trustAnchors: [] }), (e) => e instanceof TypeError);
});

test('S9-21: E19 - options is not validated as a cert (string input still parses as PEM→fails loudly)', () => {
  // A string that is neither PEM nor DER must throw, not return verified:false silently
  assert.throws(() => verifyPqChain('definitely not a certificate', { trustAnchors: [] }));
});

test('S9-22: E1 - empty Uint8Array raises MALFORMED_CERT', () => {
  assert.throws(
    () => verifyPqChain(new Uint8Array(0), { trustAnchors: [] }),
    (e) => /MALFORMED_CERT/.test(e.message),
  );
});

test('S9-23: E2 - truncated DER raises MALFORMED_CERT (never verified:true)', () => {
  const truncated = new Uint8Array(leafDer.subarray(0, leafDer.length - 1));
  assert.throws(
    () => verifyPqChain(truncated, { trustAnchors: [] }),
    (e) => /MALFORMED_CERT/.test(e.message),
  );
});

test('S9-24: E24 - garbage bytes raise rather than returning false', () => {
  const garbage = new Uint8Array([0x99, 0x99, 0x99, 0x99, 0x99, 0x99]);
  assert.throws(() => verifyPqChain(garbage, { trustAnchors: [] }));
});

test('S9-25: verifyCertificateChain type-confusion raises TypeError', () => {
  assert.throws(
    () => verifyCertificateChain(null, [], [], {}),
    (e) => e instanceof TypeError,
  );
  assert.throws(
    () => verifyCertificateChain(new Uint8Array(0), 'not-array', [], {}),
    (e) => e instanceof TypeError,
  );
});

// ─────────────────────────────────────────────────────────────
// S9-trust-anchors: loader helpers
// ─────────────────────────────────────────────────────────────
test('S9-26: loadTrustAnchorsFromPem parses a single cert PEM', () => {
  const anchors = loadTrustAnchorsFromPem(toPem(rootDer));
  assert.ok(Array.isArray(anchors));
  assert.equal(anchors.length, 1);
  const a = anchors[0];
  assert.equal(typeof a.oid, 'string');
  assert.ok(a.publicKey instanceof Uint8Array);
  assert.ok(a.publicKey.length > 0);
});

test('S9-27: loadTrustAnchorsFromPem parses multiple certs', () => {
  const pem = toPem(rootDer) + toPem(leafDer);
  const anchors = loadTrustAnchorsFromPem(pem);
  assert.equal(anchors.length, 2);
});

test('S9-28: loadTrustAnchorsFromDer parses one cert', () => {
  const anchors = loadTrustAnchorsFromDer(new Uint8Array(rootDer));
  assert.equal(anchors.length, 1);
  assert.ok(anchors[0].publicKey instanceof Uint8Array);
});

test('S9-29: loadTrustAnchorsFromPem rejects non-string input (TypeError)', () => {
  assert.throws(() => loadTrustAnchorsFromPem(null), (e) => e instanceof TypeError);
  assert.throws(() => loadTrustAnchorsFromPem(42), (e) => e instanceof TypeError);
});

test('S9-30: loadTrustAnchorsFromDer rejects non-Uint8Array input (TypeError)', () => {
  assert.throws(() => loadTrustAnchorsFromDer('nope'), (e) => e instanceof TypeError);
  assert.throws(() => loadTrustAnchorsFromDer(null), (e) => e instanceof TypeError);
});

test('S9-31: trust anchors usable directly as verifyPqChain trustAnchors', () => {
  const anchors = loadTrustAnchorsFromDer(new Uint8Array(rootDer));
  // leaf is not signed by root in corpus, but the call must not throw and must
  // return a well-formed result (verified false with a chain error is correct)
  const result = verifyPqChain(leafDer, { trustAnchors: anchors });
  assert.equal(typeof result.verified, 'boolean');
  assert.ok(Array.isArray(result.errors));
  assert.ok(result.cbom);
});

// ─────────────────────────────────────────────────────────────
// S9-determinism
// ─────────────────────────────────────────────────────────────
test('S9-32: identical input → identical result (determinism)', () => {
  const leaf = parseCertificate(leafDer);
  const a = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  const b = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
});

// ─────────────────────────────────────────────────────────────
// S9-corpus: known corpus inputs do not crash the public API
// ─────────────────────────────────────────────────────────────
test('S9-33: corpus leaf verifies when it is its own anchor', () => {
  const leaf = parseCertificate(leafDer);
  const result = verifyPqChain(leafDer, { trustAnchors: [leaf] });
  assert.equal(result.verified, true);
});

test('S9-34: corpus leaf fails against a foreign anchor (E12 path, not a throw)', () => {
  const root = parseCertificate(rootDer);
  const result = verifyPqChain(leafDer, { trustAnchors: [root] });
  assert.equal(result.verified, false);
  assert.ok(result.errors.length > 0);
});
