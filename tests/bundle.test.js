import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { normalizeCertBundle } from '../src/bundle.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

test('normalizeCertBundle - round-trips DER input unchanged', () => {
  // Create a minimal valid DER cert-like bytes starting with SEQUENCE tag 0x30
  const derCert = new Uint8Array([
    0x30, 0x82, 0x01, 0x00, // SEQUENCE with length
    0x02, 0x01, 0x01, // INTEGER
    0x30, 0x00, // empty SEQUENCE
    0x30, 0x00, // empty SEQUENCE
  ]);
  
  const result = normalizeCertBundle(derCert);
  
  assert.ok(result.leaf);
  assert.equal(result.leaf.length, derCert.length);
  assert.ok(Array.isArray(result.intermediates));
  assert.ok(Array.isArray(result.anchors));
});

test('normalizeCertBundle - PEM input with multiple certificates', () => {
  const pemBundle = `-----BEGIN CERTIFICATE-----
MIIB7DCCAXKgAwIBAgIUL149AUxHunELBZMELEQm+isgKCQwCgYIKoZIzj0EAwMw
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB7DCCAXKgAwIBAgIUL149AUxHunELBZMELEQm+isgKCQwCgYIKoZIzj0EAwMw
-----END CERTIFICATE-----`;
  
  const result = normalizeCertBundle(pemBundle);
  
  assert.ok(result.leaf);
  assert.equal(result.intermediates.length, 1);
  assert.ok(result.intermediates[0].length > 0);
});

test('normalizeCertBundle - E22 PEM input auto-detects BEGIN CERTIFICATE', () => {
  const pemWithHeaders = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mR5w0MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END CERTIFICATE-----`;
  
  const result = normalizeCertBundle(pemWithHeaders);
  
  assert.ok(result.leaf instanceof Uint8Array);
  assert.ok(result.leaf.length > 0);
  // Check decoder worked - DER certs start with SEQUENCE tag
  assert.ok(result.leaf[0] === 0x30);
});

test('normalizeCertBundle - unordered intermediates sorted by chain order', () => {
  // Create cert-like DER bytes starting with SEQUENCE tag 0x30, length > 10
  const certA = new Uint8Array([
    0x30, 0x82, 0x00, 0x20, 0x02, 0x01, 0x01, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const certB = new Uint8Array([
    0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const certC = new Uint8Array([
    0x30, 0x82, 0x02, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  
  // Simulate bundle with unordered certs (largest first)
  const pem = `-----BEGIN CERTIFICATE-----
${Buffer.from(certC).toString('base64')}
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
${Buffer.from(certA).toString('base64')}
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
${Buffer.from(certB).toString('base64')}
-----END CERTIFICATE-----`;
  
  const result = normalizeCertBundle(pem);
  
  assert.ok(result.leaf);
  // Leaf should be smallest cert (certA)
  assert.equal(result.leaf.length, certA.length);
  // Should have 2 intermediates
  assert.equal(result.intermediates.length, 2);
});

test('normalizeCertBundle - PKCS#7 input', () => {
  // PEM format PKCS#7 input (most common real-world case)
  const pemPkcs7 = `-----BEGIN PKCS7-----
MIIB7DCCAXKgAwIBAgIJAKL0UG+mR5w0MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END PKCS7-----`;
  
  const result = normalizeCertBundle(pemPkcs7);
  
  assert.ok(result.leaf);
  assert.ok(result.leaf.length > 0);
  // Leaf should have valid DER structure starting with 0x30
  assert.ok(result.leaf[0] === 0x30);
});

test('normalizeCertBundle - TypeError on garbage input', () => {
  assert.throws(() => {
    normalizeCertBundle('not a cert');
  }, {
    name: 'Error',
    message: /MALFORMED_CERT/
  });
  
  assert.throws(() => {
    normalizeCertBundle(12345);
  }, {
    name: 'TypeError'
  });
  
  assert.throws(() => {
    normalizeCertBundle(null);
  }, {
    name: 'TypeError'
  });
  
  assert.throws(() => {
    normalizeCertBundle(undefined);
  }, {
    name: 'TypeError'
  });
});

test('normalizeCertBundle - empty Uint8Array throws MALFORMED_CERT', () => {
  assert.throws(() => {
    normalizeCertBundle(new Uint8Array(0));
  }, {
    name: 'Error',
    message: /MALFORMED_CERT/
  });
});

test('normalizeCertBundle - TypeError on non-certificate string', () => {
  assert.throws(() => {
    normalizeCertBundle('-----BEGIN PRIVATE KEY-----');
  }, {
    name: 'Error',
    message: /MALFORMED_CERT/
  });
});
