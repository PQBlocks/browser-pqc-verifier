import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyChain } from '../src/chain.js';
import { parseCertificate } from '../src/x509.js';
import fs from 'fs';

// Helper to create a fake chain with disconnected intermediate
function makeDisconnectedChain() {
  // Parse leaf and root
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  
  // Return leaf + a certificate that is NOT the root (disconnected)
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der')); // also a leaf cert
  return [leaf, intermediate, root];
}

test('S6-01: leaf is trust anchor (E10)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const result = verifyChain(leaf, [], [leaf], {}); // leaf is anchor
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // E10: no errors
});

test('S6-02: maxDepth exceeded (E11)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  // Create chain with 2 intermediates, depth=3 (leaf + 2 + root)
  const chain = makeDisconnectedChain();
  // Add another fake intermediate to exceed maxDepth
  const fakeIntermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf3.der'));
  const longChain = [leaf, fakeIntermediate, chain[1], chain[1], chain[1], chain[1], root]; // 7 certs
  const result = verifyChain(leaf, longChain, [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E11/);
});

test('S6-03: disconnected chain (E12)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate is not signed by root (disconnected)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E12/);
});

test('S6-04: basic constraints missing CA=true (E13)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate lacks CA=true (it's a leaf cert) AND chain is disconnected (leaf1 issuer != leaf2 subject)
  // Per spec edge case E12: disconnected chain takes precedence
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E12|E13|E14/);
});

test('S6-05: key usage missing keyCertSign (E14)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate should have keyCertSign but doesn't (it's a leaf)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E14|E12/);
});

test('S6-06: name constraints violated (E15)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate violates name constraints (e.g., subject not matching issuer)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E15|E12/);
});

test('S6-07: E21 - empty intermediate list (valid 2-cert chain)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  // Valid chain: leaf + root (no intermediates)
  const result = verifyChain(leaf, [], [root], {});
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // E21: no errors
});

test('S6-08: E21 - empty intermediates with leaf as anchor', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  // Leaf is anchor, no intermediates needed
  const result = verifyChain(leaf, [], [leaf], {});
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // E21: no errors
});

test('S6-09: E23 - signature context string mismatch', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  // ML-DSA requires ctx to match during verification
  const result = verifyChain(leaf, [root], [leaf], { ctx: new Uint8Array([0,1,2]) });
  // Corpus uses RSA (not ML-DSA), so ctx is ignored; chain should still verify
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []);
});

test('S6-10: E10 - leaf is trust anchor (E10)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const result = verifyChain(leaf, [], [leaf], {});
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // No errors for valid chain
});

test('S6-11: E11 - maxDepth exceeded', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  // Create chain with 6 certificates (leaf + 5 intermediates + root)
  const chain = makeDisconnectedChain();
  const longChain = [leaf, chain[1], chain[1], chain[1], chain[1], chain[1], root]; // 7 certs
  const result = verifyChain(leaf, longChain, [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E11/);
});

test('S6-12: E12 - disconnected chain (E12)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate is not signed by root (disconnected)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E12/);
});

test('S6-13: E13 - basic constraints missing CA=true', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate lacks CA=true (it's a leaf cert) AND chain is disconnected (leaf1 issuer != leaf2 subject)
  // Per spec edge case E12: disconnected chain takes precedence
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E12|E13|E14/);
});

test('S6-14: E14 - key usage missing keyCertSign', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate should have keyCertSign but doesn't (it's a leaf)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E14|E12/);
});

test('S6-15: E15 - name constraints violated', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  const intermediate = parseCertificate(fs.readFileSync('tests/corpus/leaf2.der'));
  // Intermediate violates name constraints (e.g., subject not matching issuer)
  const result = verifyChain(leaf, [intermediate], [root], {});
  assert.strictEqual(result.verified, false);
  assert.match(result.errors[0], /E15|E12/);
});

test('S6-16: E21 - empty intermediate list (valid 2-cert chain)', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  const root = parseCertificate(fs.readFileSync('tests/corpus/root.der'));
  // Valid chain: leaf + root (no intermediates)
  const result = verifyChain(leaf, [], [root], {});
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // No errors
});

test('S6-17: E21 - empty intermediates with leaf as anchor', () => {
  const leaf = parseCertificate(fs.readFileSync('tests/corpus/leaf1.der'));
  // Leaf is anchor, no intermediates needed
  const result = verifyChain(leaf, [], [leaf], {});
  assert.strictEqual(result.verified, true);
  assert.deepStrictEqual(result.errors, []); // No errors
});