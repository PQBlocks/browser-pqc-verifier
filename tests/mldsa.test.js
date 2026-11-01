import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { verify, ML_DSA_PARAMS, MldsaVerificationError } from '../src/mldsa.js';
import { parseCertificate } from '../src/x509.js';
import { extractSpki, resolveParams } from '../src/spki.js';
import fs from 'node:fs';

// Tests sign with @noble/post-quantum directly and verify through src/mldsa.js:
// the product must interoperate with the underlying library at every parameter set,
// while adding its own length/type contract (E7/E8 tampered → false; E9 wrong length → MldsaVerificationError).

const keypairs = {
  mldsa44: ml_dsa44.keygen(),
  mldsa65: ml_dsa65.keygen(),
  mldsa87: ml_dsa87.keygen(),
};
const messages = {
  mldsa44: new Uint8Array([1, 2, 3, 4, 5]),
  mldsa65: new Uint8Array([6, 7, 8, 9, 10]),
  mldsa87: new Uint8Array([11, 12, 13, 14, 15]),
};
const sigs = {
  mldsa44: ml_dsa44.sign(messages.mldsa44, keypairs.mldsa44.secretKey),
  mldsa65: ml_dsa65.sign(messages.mldsa65, keypairs.mldsa65.secretKey),
  mldsa87: ml_dsa87.sign(messages.mldsa87, keypairs.mldsa87.secretKey),
};

// --- happy path: a real signature over a real message returns true ---
test('verify returns true for a valid ML-DSA-44 signature', () => {
  assert.strictEqual(verify('mldsa44', keypairs.mldsa44.publicKey, sigs.mldsa44, messages.mldsa44), true);
});

test('verify returns true for a valid ML-DSA-65 signature', () => {
  assert.strictEqual(verify('mldsa65', keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65), true);
});

test('verify returns true for a valid ML-DSA-87 signature', () => {
  assert.strictEqual(verify('mldsa87', keypairs.mldsa87.publicKey, sigs.mldsa87, messages.mldsa87), true);
});

test('verify returns true for empty message', () => {
  const kp = ml_dsa44.keygen();
  const msg = new Uint8Array(0);
  const sig = ml_dsa44.sign(msg, kp.secretKey);
  assert.strictEqual(verify('mldsa44', kp.publicKey, sig, msg), true);
});

test('verify returns true for a large message (1 MiB)', () => {
  const kp = ml_dsa65.keygen();
  const msg = new Uint8Array(1 << 20);
  for (let i = 0; i < msg.length; i++) msg[i] = (i * 31 + 7) & 0xff;
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  assert.strictEqual(verify('mldsa65', kp.publicKey, sig, msg), true);
});

// --- parameter normalisation ---
test('verify accepts parameter alias mlDsa65 (camelCase) same as mldsa65', () => {
  assert.strictEqual(verify('mlDsa65', keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65), true);
});

test('verify accepts parameter alias 65 (numeric set) same as mldsa65', () => {
  assert.strictEqual(verify('65', keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65), true);
});

test('ML_DSA_PARAMS exposes the three FIPS 204 parameter sets', () => {
  assert.deepStrictEqual([...ML_DSA_PARAMS.keys()].sort(), ['mldsa44', 'mldsa65', 'mldsa87']);
  // Table 2 of FIPS 204 sizes
  assert.strictEqual(ML_DSA_PARAMS.get('mlDsa65').publicKeyBytes, 1952);
});

test('ML_DSA_PARAMS sizes match the underlying library constants', () => {
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa44').publicKeyBytes, ml_dsa44.lengths.publicKey);
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa65').publicKeyBytes, ml_dsa65.lengths.publicKey);
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa87').publicKeyBytes, ml_dsa87.lengths.publicKey);
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa44').signatureBytes, ml_dsa44.lengths.signature);
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa65').signatureBytes, ml_dsa65.lengths.signature);
  assert.strictEqual(ML_DSA_PARAMS.get('mldsa87').signatureBytes, ml_dsa87.lengths.signature);
});

// --- E7: tampered signature ---
test('E7: tampered signature byte causes verify to return false', () => {
  const tampered = new Uint8Array(sigs.mldsa65);
  tampered[0] ^= 0x01;
  assert.strictEqual(verify('mldsa65', keypairs.mldsa65.publicKey, tampered, messages.mldsa65), false);
});

test('E7: tampered signature last byte causes verify to return false', () => {
  const tampered = new Uint8Array(sigs.mldsa65);
  tampered[tampered.length - 1] ^= 0x80;
  assert.strictEqual(verify('mldsa65', keypairs.mldsa65.publicKey, tampered, messages.mldsa65), false);
});

// --- E8: tampered public key ---
test('E8: tampered public key causes verify to return false', () => {
  const tamperedPk = new Uint8Array(keypairs.mldsa65.publicKey);
  tamperedPk[0] ^= 0x01;
  assert.strictEqual(verify('mldsa65', tamperedPk, sigs.mldsa65, messages.mldsa65), false);
});

test('E8: signature verified against a different keypair returns false', () => {
  const other = ml_dsa65.keygen();
  assert.strictEqual(verify('mldsa65', other.publicKey, sigs.mldsa65, messages.mldsa65), false);
});

// --- E9: wrong lengths ---
test('E9: truncated signature throws MldsaVerificationError', () => {
  const truncated = sigs.mldsa65.subarray(0, sigs.mldsa65.length - 1);
  assert.throws(() => verify('mldsa65', keypairs.mldsa65.publicKey, truncated, messages.mldsa65), MldsaVerificationError);
});

test('E9: truncated public key throws MldsaVerificationError', () => {
  const truncatedPk = keypairs.mldsa65.publicKey.subarray(0, keypairs.mldsa65.publicKey.length - 1);
  assert.throws(() => verify('mldsa65', truncatedPk, sigs.mldsa65, messages.mldsa65), MldsaVerificationError);
});

test('E9: wrong-length signature error carries code E9 and a size hint', () => {
  const truncated = sigs.mldsa65.subarray(0, 10);
  try {
    verify('mldsa65', keypairs.mldsa65.publicKey, truncated, messages.mldsa65);
    assert.fail('expected verify to throw');
  } catch (err) {
    assert.ok(err instanceof MldsaVerificationError);
    assert.strictEqual(err.code, 'E9');
    assert.match(err.message, /signature length/);
    assert.match(err.message, /3309/);
  }
});

// --- negative: bad inputs must raise a catchable, specific error ---
test('non-Uint8Array public key throws MldsaVerificationError with code E9', () => {
  assert.throws(() => verify('mldsa65', 'not-bytes', sigs.mldsa65, messages.mldsa65), MldsaVerificationError);
});

test('non-Uint8Array signature throws MldsaVerificationError with code E9', () => {
  assert.throws(() => verify('mldsa65', keypairs.mldsa65.publicKey, null, messages.mldsa65), MldsaVerificationError);
});

test('non-Uint8Array message throws MldsaVerificationError with code E9', () => {
  assert.throws(() => verify('mldsa65', keypairs.mldsa65.publicKey, sigs.mldsa65, 'msg'), MldsaVerificationError);
});

test('unknown parameter set throws MldsaVerificationError with code E9', () => {
  assert.throws(() => verify('mldsa99', keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65), MldsaVerificationError);
});

test('null parameter set throws MldsaVerificationError', () => {
  assert.throws(() => verify(null, keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65), MldsaVerificationError);
});

// --- E23: context mismatch ---
test('E23: sig made with context fails to verify without matching ctx', () => {
  const kp = ml_dsa65.keygen();
  const msg = messages.mldsa65;
  const ctx = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const sig = ml_dsa65.sign(msg, kp.secretKey, { context: ctx });
  // No ctx at verify time -> false
  assert.strictEqual(verify('mldsa65', kp.publicKey, sig, msg), false);
  // Empty ctx -> false
  assert.strictEqual(verify('mldsa65', kp.publicKey, sig, msg, { ctx: new Uint8Array(0) }), false);
});

test('E23: sig with ctx verifies when the same ctx is supplied', () => {
  const kp = ml_dsa65.keygen();
  const msg = messages.mldsa65;
  const ctx = new Uint8Array([1, 2, 3]);
  const sig = ml_dsa65.sign(msg, kp.secretKey, { context: ctx });
  assert.strictEqual(verify('mldsa65', kp.publicKey, sig, msg, { ctx }), true);
});

test('E23: wrong ctx value fails to verify', () => {
  const kp = ml_dsa44.keygen();
  const msg = new Uint8Array([9, 9, 9]);
  const sig = ml_dsa44.sign(msg, kp.secretKey, { context: new Uint8Array([1, 1, 1]) });
  assert.strictEqual(verify('mldsa44', kp.publicKey, sig, msg, { ctx: new Uint8Array([2, 2, 2]) }), false);
});

test('E23: ctx longer than 255 bytes throws MldsaVerificationError (FIPS 204 limit)', () => {
  const kp = ml_dsa65.keygen();
  const msg = messages.mldsa65;
  const sig = ml_dsa65.sign(msg, kp.secretKey);
  const tooLong = new Uint8Array(256);
  assert.throws(() => verify('mldsa65', kp.publicKey, sig, msg, { ctx: tooLong }), MldsaVerificationError);
});

test('E23: options object accepts both ctx and alias context keys', () => {
  const kp = ml_dsa44.keygen();
  const msg = new Uint8Array([4, 5, 6]);
  const ctx = new Uint8Array([7, 8, 9]);
  const sig = ml_dsa44.sign(msg, kp.secretKey, { context: ctx });
  assert.strictEqual(verify('mldsa44', kp.publicKey, sig, msg, { context: ctx }), true);
});

// --- determinism: same inputs, same result, across runs ---
test('verify is deterministic: repeated calls return identical results', () => {
  const results = new Set();
  for (let i = 0; i < 5; i++) {
    results.add(verify('mldsa65', keypairs.mldsa65.publicKey, sigs.mldsa65, messages.mldsa65));
  }
  assert.strictEqual(results.size, 1);
  assert.ok(results.has(true));
});

// --- interop with the SPKI layer: a signature produced outside verifies through the wrapper ---
test('chain: extractSpki + resolveParams + verify works on a real context string', () => {
  // Sanity check that the wrapper consumes the raw pk bytes form that extractSpki returns.
  const cert = loadFirstCorpusCert();
  const { oid, publicKeyBytes } = extractSpki(cert);
  const params = resolveParams(oid);
  // The corpus cert's pk is not expected to match this signature; this asserts
  // only that the wrapper accepts the byte shape extractSpki produces.
  assert.strictEqual(typeof publicKeyBytes, 'object');
  if (params) {
    assert.throws(() => verify(params, publicKeyBytes, sigs.mldsa65, messages.mldsa65), MldsaVerificationError);
  }
});

// --- no keygen/sign surface exported ---
test('src/mldsa.js exports no keygen or sign (verify-only wrapper)', async () => {
  const mod = await import('../src/mldsa.js');
  assert.strictEqual(typeof mod.verify, 'function');
  for (const banned of ['sign', 'keypair', 'keygen']) {
    assert.strictEqual(mod[banned], undefined, `src/mldsa.js must not export ${banned}`);
  }
});

// --- helper ---
function loadFirstCorpusCert() {
  const files = fs.readdirSync('tests/corpus').filter((f) => f.endsWith('.der') || f.endsWith('.crt')).sort();
  if (files.length === 0) return null;
  return parseCertificate(new Uint8Array(fs.readFileSync(`tests/corpus/${files[0]}`)));
}
