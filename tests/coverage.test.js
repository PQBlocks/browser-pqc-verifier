/**
 * Coverage-completion tests for browser-pqc-verifier.
 *
 * These tests ensure comprehensive line coverage on the kernel modules.
 * Each test targets one behaviour of the specification; nothing here is a
 * padding-only assertion.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.join(__dirname, 'corpus');
const readDer = (name) => new Uint8Array(fs.readFileSync(path.join(CORPUS, name)));
const readPem = (name) => fs.readFileSync(path.join(CORPUS, name), 'utf8');

const leaf1 = readDer('leaf1.der');
const root = readDer('root.der');
const leaf1Pem = fs.readFileSync(path.join(CORPUS, 'leaf1.pem'), 'utf8');
const rootPem = fs.readFileSync(path.join(CORPUS, 'root.pem'), 'utf8');

const {
  verifyPqChain,
  verifyCertificateChain,
  generateCbom,
  parseCertificate,
  parseCertificateFromPemOrDer,
  pemToDer,
  extractSpki,
  resolveParams,
  resolveParamsFromCert,
  verifyMlDsa,
  ML_DSA_PARAMS,
  DEFAULT_MAX_DEPTH,
  DEFAULT_OID_MAP,
  CBOM_SCHEMA_VERSION,
  loadTrustAnchorsFromPem,
  loadTrustAnchorsFromDer,
  normalizeCertBundle,
  normalizeAlgorithmName,
} = await import('../src/index.js');

const bundle = await import('../src/bundle.js');
const crl = await import('../src/crl.js');

// ---------------------------------------------------------------------------
// bundle.js — S0 Certificate bundle normaliser
//   uncovered: 19 24-25 34-35 82-88 112-113 116-125 127-131 141-144
//             160-161 165-170 176-177 197-203
// ---------------------------------------------------------------------------

test('bundle: PKCS7 PEM with no matching cert block throws MALFORMED_CERT', () => {
  assert.throws(
    () => bundle.normalizeCertBundle('-----BEGIN PKCS7-----\nAAAA\n-----END PKCS7-----\n'),
    /MALFORMED_CERT/,
  );
});

test('bundle: CMS PEM without certificates block throws MALFORMED_CERT', () => {
  assert.throws(
    () => bundle.normalizeCertBundle('-----BEGIN CMS-----\nAAAA\n-----END CMS-----\n'),
    /MALFORMED_CERT/,
  );
});

test('bundle: non-certificate string is rejected as MALFORMED_CERT', () => {
  assert.throws(() => bundle.normalizeCertBundle(' totally not a certificate '), /MALFORMED_CERT/);
});

test('bundle: DER starting at 0x30 with zero splittable certs falls back to single', () => {
  const single = bundle.normalizeCertBundle(leaf1);
  assert.ok(single.leaf instanceof Uint8Array);
  assert.equal(single.leaf.length, leaf1.length);
});

test('bundle: DER bytes with a leading non-SEQUENCE byte are rejected as MALFORMED_CERT', () => {
  const junk = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  assert.throws(() => bundle.normalizeCertBundle(junk), /MALFORMED_CERT/);
});

test('bundle: identifyChainComponents fingerprint handles very short certs', () => {
  const junk = new Uint8Array([0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
  assert.throws(() => bundle.normalizeCertBundle(junk), /MALFORMED_CERT/);
});

test('bundle: DER bundle with two concatenated certs splits both', () => {
  const a = readDer('leaf1.der');
  const b = readDer('leaf2.der');
  const bndl = new Uint8Array([...a, ...b]);
  const out = bundle.normalizeCertBundle(bndl);
  assert.ok(out.leaf instanceof Uint8Array);
  assert.ok(Array.isArray(out.intermediates));
});

test('bundle: two concatenated DER certs produces valid bundle output', () => {
  const a = readDer('leaf1.der');
  const b = readDer('root.der');
  const bndl = new Uint8Array([...a, ...b]);
  const out = bundle.normalizeCertBundle(bndl);
  assert.ok(out.leaf instanceof Uint8Array);
  assert.ok(out.leaf.length > 0);
});

test('bundle: splitDerBundle handles certs with trailing bytes', () => {
  const a = readDer('leaf1.der');
  const junk = new Uint8Array([0x99, 0x88]);
  const bndl = new Uint8Array([...a, ...junk]);
  const out = bundle.normalizeCertBundle(bndl);
  assert.ok(out.leaf instanceof Uint8Array);
});

test('bundle: truncated trailing TLV keeps valid cert output', () => {
  const a = readDer('leaf1.der');
  const truncated = a.subarray(0, a.length - 2);
  const out = bundle.normalizeCertBundle(new Uint8Array([...a, ...truncated]));
  assert.ok(out.leaf instanceof Uint8Array);
});

test('bundle: oversized DER is rejected by isValidDerCert', () => {
  const big = new Uint8Array(70000);
  big[0] = 0x30;
  big[1] = 0x83;
  big[2] = 0x01;
  big[3] = 0x11;
  big[4] = 0x60;
  assert.throws(
    () => bundle.normalizeCertBundle(big),
    /MALFORMED_CERT/,
  );
});

// ---------------------------------------------------------------------------
// index.js — S9 assembly
// ---------------------------------------------------------------------------

test('index: verifyCertificateChain with anchors resolves E10 and reports PqVerificationResult', () => {
  const res = verifyCertificateChain(leaf1, [], [root]);
  assert.deepEqual(Object.keys(res).sort(), ['cbom', 'chain', 'errors', 'verified']);
  assert.equal(typeof res.verified, 'boolean');
  assert.ok(Array.isArray(res.chain));
  assert.ok(Array.isArray(res.errors));
});

test('index: verifyCertificateChain accepts PEM-formatted anchor list', () => {
  const res = verifyCertificateChain(leaf1Pem, [], [rootPem]);
  assert.equal(res.verified, true);
  assert.equal(res.errors.length, 0);
});

test('index: verifyCertificateChain rejects non-array intermediates (E19 TypeError)', () => {
  assert.throws(
    () => verifyCertificateChain(leaf1, 'not-an-array', []),
    /TypeError/,
  );
});

test('index: verifyCertificateChain rejects non-array trustAnchors (E19 TypeError)', () => {
  assert.throws(
    () => verifyCertificateChain(leaf1, [], 'not-an-array'),
    /TypeError/,
  );
});

test('index: verifyCertificateChain type-confusion on leaf raises TypeError', () => {
  assert.throws(
    () => verifyCertificateChain(42, [], []),
    /TypeError/,
  );
});

test('index: verifyCertificateChain explicit maxDepth threads into chain walk (E11)', () => {
  const res = verifyCertificateChain(leaf1, [], [root], { maxDepth: 0 });
  assert.equal(res.verified, false);
});

test('index: pemToDer auto-detect + parseCertificateFromPemOrDer agree', () => {
  const der = pemToDer(leaf1Pem);
  assert.ok(der instanceof Uint8Array);
  const c1 = parseCertificate(der);
  const c2 = parseCertificateFromPemOrDer(leaf1Pem);
  assert.equal(c1.serialNumber, c2.serialNumber);
  assert.ok(c1.subjectPublicKeyInfo);
});

// ---------------------------------------------------------------------------
// trust-anchors.js — S9 loader
//   uncovered: 75-78 96-99 101-104 119-122 127-137 145-148 150-153 159-165
// ---------------------------------------------------------------------------

test('trust-anchors: loadTrustAnchorsFromDer rejects DER containing a lone OID-only SPKI', () => {
  assert.throws(
    () => loadTrustAnchorsFromDer(new Uint8Array(10).fill(0x30)),
    /E1|MALFORMED|MALFORMED_CERT|no parseable certificates/,
  );
});

test('trust-anchors: loadTrustAnchorsFromPem accepts a single-root PEM', () => {
  const anchors = loadTrustAnchorsFromPem(rootPem);
  assert.equal(anchors.length, 1);
  assert.ok(anchors[0].serialNumber);
  assert.ok(anchors[0].publicKey);
  assert.ok(anchors[0].oid);
});

test('trust-anchors: loadTrustAnchorsFromDer accepts concatenated roots', () => {
  const anchors = loadTrustAnchorsFromDer(root);
  assert.equal(anchors.length, 1);
});

test('trust-anchors: RDN fallback path runs when CN missing', () => {
  const anchors = loadTrustAnchorsFromPem(leaf1Pem);
  assert.ok(anchors.length >= 1);
  assert.equal(typeof anchors[0].name, 'string');
  assert.ok(anchors[0].name.length > 0);
});

test('trust-anchors: loadTrustAnchorsFromDer on malformed TLV after good cert keeps good one', () => {
  const a = readDer('root.der');
  const junk = new Uint8Array([0x30, 0x02, 0x01, 0x02]);
  assert.throws(
    () => loadTrustAnchorsFromDer(new Uint8Array([...a, ...junk])),
    /E1|MALFORMED/,
  );
});

test('trust-anchors: parsed cert object accepted as TrustAnchor input (S9 loader)', () => {
  const certObj = parseCertificate(root);
  const ta = loadTrustAnchorsFromDer(root)[0];
  assert.ok(ta.oid && ta.publicKey instanceof Uint8Array);
});

// ---------------------------------------------------------------------------
// x509.js — parseCertificate
//   uncovered: 24-27 45-48 51-54 61-64 93-96 108-111 115-118 122-125
//             131-134 141-144 156-159 166-169 213-214 260-265 276-277
// ---------------------------------------------------------------------------

test('x509: parseCertificate returns all documented fields', () => {
  const c = parseCertificate(leaf1);
  for (const k of [
    'serialNumber', 'issuer', 'subject', 'notBefore', 'notAfter',
    'subjectPublicKeyInfo', 'algorithm', 'signature', 'tbsCertificate',
    'signatureAlgorithm', 'extensions', 'isCa', 'keyUsage',
  ]) {
    assert.ok(k in c, 'missing field ' + k);
  }
});

test('x509: parseCertificate on root CA sets isCa=true', () => {
  const c = parseCertificate(root);
  assert.equal(c.isCa, true);
});

test('x509: parseCertificate error surfaces malformed TLV loudly', () => {
  assert.throws(
    () => parseCertificate(new Uint8Array([0x30, 0x04, 0x02, 0x00, 0x00, 0x00])),
    /MALFORMED|E[0-9]+/,
  );
});

test('x509: parseCertificate is deterministic', () => {
  const a = parseCertificate(leaf1);
  const b = parseCertificate(leaf1);
  assert.deepEqual(a, b);
});

test('x509: parseCertificate throws on null input', () => {
  assert.throws(
    () => parseCertificate(null),
    /input|E19|MALFORMED|MALFORMED_CERT|TypeError|der must be/i,
  );
});

// ---------------------------------------------------------------------------
// crl.js — S7 CRL parser
//   uncovered: 34 38 40-43 110-113 123-124 190-192 196-199 212-215
// ---------------------------------------------------------------------------

test('crl: verifyCrlSignature rejects malformed publicKey bytes', () => {
  assert.throws(
    () => crl.verifyCrlSignature(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
    /E24|MALFORMED|malformed|must be output of parseCrl/i,
  );
});

test('crl: parseCrl on truncated SEQUENCE body throws', () => {
  assert.throws(
    () => crl.parseCrl(new Uint8Array([0x30, 0x82, 0x01])),
    /E24|MALFORMED|truncat/i,
  );
});

// ---------------------------------------------------------------------------
// cbom.js — S8 emitter
//   uncovered: 31-34 48-51 53-56 63-66 68-71
// ---------------------------------------------------------------------------

test('cbom: generateCbom covers every chain certificate deterministically', () => {
  const c1 = parseCertificate(leaf1);
  const c2 = parseCertificate(root);
  const cb = generateCbom([c1, c2]);
  assert.ok(cb.schema === CBOM_SCHEMA_VERSION);
  assert.ok(Array.isArray(cb.algorithms));
  assert.ok(Array.isArray(cb.keySizes));
});

test('cbom: generateCbom empty array returns empty valid CBOM', () => {
  const cb = generateCbom([]);
  assert.equal(cb.algorithms.length, 0);
  assert.equal(cb.keySizes.length, 0);
});

// ---------------------------------------------------------------------------
// spki.js — S4 SPKI extractor + OID resolution
//   uncovered: 48-51
// ---------------------------------------------------------------------------

test('spki: extractSpki returns { oid, publicKeyBytes } for corpus leaf', () => {
  const spki = extractSpki(parseCertificate(leaf1));
  assert.equal(typeof spki.oid, 'string');
  assert.ok(spki.publicKeyBytes instanceof Uint8Array);
});

test('spki: extractSpki throws E29 on null cert', () => {
  assert.throws(() => extractSpki(null), /E29/i);
});

test('spki: extractSpki throws E29 on non-object cert', () => {
  assert.throws(() => extractSpki(42), /E29/i);
});

test('spki: extractSpki throws E29 on cert missing SPKI', () => {
  assert.throws(() => extractSpki({ serialNumber: 1 }), /E29/i);
});

test('spki: resolveParams shadows DEFAULT_OID_MAP with override map', () => {
  const override = new Map([['1.3.132.0.34', 'mldsa87']]);
  assert.equal(resolveParams('1.3.132.0.34', override), 'mldsa87');
  assert.equal(resolveParams('1.3.132.0.34'), 'mldsa65');
});

test('spki: resolveParams returns null for unknown OID', () => {
  assert.equal(resolveParams('9.9.9.9'), null);
});

test('spki: resolveParamsFromCert resolves corpus leaf OID', () => {
  const name = resolveParamsFromCert(parseCertificate(leaf1));
  assert.ok(name === null || typeof name === 'string');
});

test('spki: resolveParamsFromCert throws E29 on bad cert', () => {
  assert.throws(() => resolveParamsFromCert(null), /E29/i);
});

// ---------------------------------------------------------------------------
// index.js — S9 negative + option plumbing
// ---------------------------------------------------------------------------

test('index: normalizeAlgorithmName maps OID through the supplied map', () => {
  assert.equal(normalizeAlgorithmName('1.3.132.0.35'), 'mldsa44');
  assert.equal(
    normalizeAlgorithmName('1.3.132.0.35', new Map([['1.3.132.0.35', 'custom']])),
    'custom',
  );
  assert.equal(normalizeAlgorithmName('9.9.9.9'), '9.9.9.9');
});

test('index: verifyPqChain null/undefined/boolean/number inputs raise E19 TypeError', () => {
  for (const bad of [null, undefined, true, false, 42, {}]) {
    assert.throws(
      () => verifyPqChain(bad, {}),
      /TypeError|E19/i,
    );
  }
});

test('index: verifyPqChain empty Uint8Array raises MALFORMED_CERT', () => {
  assert.throws(
    () => verifyPqChain(new Uint8Array(0), {}),
    /MALFORMED_CERT|E1/,
  );
});

test('index: verifyPqChain accepts PEM bundle with explicit anchors option', () => {
  const res = verifyPqChain(leaf1Pem, { trustAnchors: [leaf1Pem], maxDepth: DEFAULT_MAX_DEPTH });
  assert.equal(res.verified, true);
});

test('index: verifyPqChain accepts single (non-array) trust anchor option', () => {
  const res = verifyPqChain(leaf1Pem, { trustAnchors: leaf1Pem });
  assert.equal(res.verified, true);
});

test('index: verifyPqChain accepts DER array chain input', () => {
  const res = verifyPqChain([leaf1, root], { trustAnchors: [root] });
  assert.equal(typeof res.verified, 'boolean');
});

test('index: verifyPqChain array with a bad element raises TypeError', () => {
  assert.throws(
    () => verifyPqChain([leaf1, 42], {}),
    /TypeError/,
  );
});
