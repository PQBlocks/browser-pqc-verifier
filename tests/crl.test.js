/**
 * CRL parsing and revocation check tests.
 * Suite S7-01 .. S7-20
 *
 * E18 = certificate revoked (serial in revokedCertificates)
 * E24 = malformed CRL (bad ASN.1 / missing fields / bad sig)
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  parseCrl,
  isRevoked,
  verifyCrlSignature,
} from '../src/crl.js'

const here = dirname(fileURLToPath(import.meta.url))
const corpus = join(here, 'corpus')

/** helper: build a DER INTEGER from hex string */
function derInt(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substring(i, i + 2), 16))
  while (bytes.length > 1 && bytes[0] === 0) bytes.shift()
  return Buffer.from([0x02, bytes.length, ...bytes])
}

/** helper: build a minimal DER UTCTime */
function derUtc(y, m, d) {
  const s = `${
    String(y % 100).padStart(2, '0')}${String(m).padStart(2, '0')}${String(d).padStart(2, '0')}000000Z`
  const bytes = Buffer.from(s)
  return Buffer.concat([Buffer.from([0x17, bytes.length]), bytes])
}

/** helper: DER SEQUENCE of supplied buffers */
function derSeq(...parts) {
  const body = Buffer.concat(parts)
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}

/** helper: build a CertificateList CRL */
function buildCrl({ serials = ['01'], revoked = true, sigAlgOid = '2.16.840.1.101.3.4.3.17' } = {}) {
  // signature AlgorithmIdentifier
  const sigAlg = derSeq(Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]))

  // issuer Name: RDNSequence with one CN
  const cnOid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]) // 2.5.4.3 CN
  const cnVal = Buffer.concat([Buffer.from([0x0c, 8]), Buffer.from('TestCRLI')])
  const rdn = derSeq(derSeq(cnOid, cnVal))
  const issuer = rdn

  // thisUpdate
  const thisUpdate = derUtc(2026, 9, 15)

  // revokedCertificates (SEQUENCE OF SEQUENCE { serial, date })
  let revokedCerts = Buffer.alloc(0)
  if (revoked) {
    const inner = []
    for (const s of serials) inner.push(derSeq(derInt(s), derUtc(2026, 9, 1)))
    revokedCerts = derSeq(...inner)
  }

  // tbsCertificateList SEQUENCE
  const tbs = derSeq(Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]), // version v2
    sigAlg,
    issuer,
    thisUpdate,
    revokedCerts,
  ]))

  // CRL = tbs || sigAlg || sig BIT STRING
  const sigBytes = Buffer.alloc(3309) // ML-DSA-65 sig size
  const sigBs = Buffer.concat([Buffer.from([0x03, 0x82, 0x0c, 0xed, 0x00]), sigBytes])
  return Buffer.concat([tbs, sigAlg, sigBs])
}

// ─────────────────────────────────────────────────────────────
// S7-parse: happy path
// ─────────────────────────────────────────────────────────────
test('S7-01: parses CRL serial into Set and thisUpdate', () => {
  const crl = parseCrl(buildCrl())
  assert.equal(crl.revokedSerials.has('01'), true)
  assert.equal(crl.revokedSerials.size, 1)
  assert.ok(crl.thisUpdate instanceof Date)
  assert.equal(crl.thisUpdate.getUTCFullYear(), 2026)
  assert.equal(crl.thisUpdate.getUTCMonth(), 8) // September (0-indexed)
  assert.equal(crl.thisUpdate.getUTCDate(), 15)
})

test('S7-02: parses multiple revoked serials', () => {
  const crl = parseCrl(buildCrl({ serials: ['01', '0A', 'FF'] }))
  assert.equal(crl.revokedSerials.size, 3)
  for (const hex of ['01', '0A', 'FF']) assert.equal(crl.revokedSerials.has(hex), true)
})

test('S7-03: parses empty revokedCertificates', () => {
  const crl = parseCrl(buildCrl({ revoked: false }))
  assert.equal(crl.revokedSerials.size, 0)
})

test('S7-04: parses CRL PEM input', async () => {
  const der = buildCrl()
  const pem = '-----BEGIN X509 CRL-----\n' +
    der.toString('base64').replace(/(.{64})/g, '$1\n') +
    '-----END X509 CRL-----\n'
  const crl = parseCrl(pem)
  assert.equal(crl.revokedSerials.has('01'), true)
})

// ─────────────────────────────────────────────────────────────
// S7-revoke: E18
// ─────────────────────────────────────────────────────────────
test('S7-05: isRevoked true when serial present (E18 path)', () => {
  const crl = parseCrl(buildCrl({ serials: ['01'] }))
  assert.equal(isRevoked(crl, '01'), true)
})

test('S7-06: isRevoked false when serial absent', () => {
  const crl = parseCrl(buildCrl({ serials: ['01'] }))
  assert.equal(isRevoked(crl, '02'), false)
})

test('S7-07: isRevoked accepts Buffer serial from parsed cert', () => {
  const crl = parseCrl(buildCrl({ serials: ['0A'] }))
  assert.equal(isRevoked(crl, Buffer.from([0x0a])), true)
})

test('S7-08: isRevoked normalizes case (lowercase hex accepted)', () => {
  const crl = parseCrl(buildCrl({ serials: ['AB'] }))
  assert.equal(isRevoked(crl, 'ab'), true)
})

// ─────────────────────────────────────────────────────────────
// S7-neg: E24 malformed
// ─────────────────────────────────────────────────────────────
test('S7-09: E24 - empty buffer throws', () => {
  assert.throws(() => parseCrl(Buffer.alloc(0)), (e) => e.code === 'E24')
})

test('S7-10: E24 - wrong outer tag throws', () => {
  const buf = Buffer.from([0x31, 0x03, 0x02, 0x01, 0x01])
  assert.throws(() => parseCrl(buf), (e) => e.code === 'E24')
})

test('S7-11: E24 - non-buffer input throws', () => {
  assert.throws(() => parseCrl(42), (e) => e.code === 'E24')
})

test('S7-12: E24 - truncated SEQUENCE body throws', () => {
  const buf = Buffer.from([0x30, 0x7f, 0x02, 0x01, 0x01]) // len says 127 but only 3 bytes
  assert.throws(() => parseCrl(buf), (e) => e.code === 'E24')
})

test('S7-13: E24 - tbs missing required fields throws', () => {
  // SEQUENCE with only one INTEGER
  const bad = Buffer.concat([
    Buffer.from([0x30, 0x03]),
    Buffer.from([0x02, 0x01, 0x01]),
  ])
  assert.throws(() => parseCrl(bad), (e) => e.code === 'E24')
})

test('S7-14: E24 - non-string revoked entry throws', () => {
  const crl = parseCrl(buildCrl())
  assert.throws(() => crl.revokedSerials.has(42), TypeError)
})

test('S7-15: E24 - CRL missing signature throws', () => {
  // tbs only, no trailing sigAlg/BIT STRING
  const der = buildCrl()
  const tbs = derSeq(Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]),
    derSeq(Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11])),
    derSeq(derSeq(derSeq(Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]), Buffer.from([0x0c, 0x02, 0x41, 0x42])))),
    derUtc(2026, 9, 15),
  ]))
  assert.throws(() => parseCrl(tbs), (e) => e.code === 'E24')
})

// ─────────────────────────────────────────────────────────────
// S7-sig: signature verification
// ─────────────────────────────────────────────────────────────
test('S7-16: verifyCrlSignature rejects unknown sig algorithm with E24', () => {
  const crl = parseCrl(buildCrl())
  assert.throws(
    () => verifyCrlSignature(crl, { publicKey: Buffer.alloc(0), algorithmOid: '1.2.3.4' }),
    (e) => e.code === 'E24',
  )
})

test('S7-17: verifyCrlSignature returns false for correctly-sized key, bogus signature', async () => {
  const crl = parseCrl(buildCrl())
  const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js')
  const keygen = ml_dsa65.keygen
  const kp = keygen()
  // The CRL carries a dummy (never-signed) signature of the right length, so a
  // real 1952-byte ML-DSA-65 key must fail verification => boolean false (E7).
  const ok = verifyCrlSignature(crl, { publicKey: kp.publicKey, algorithmOid: '2.16.840.1.101.3.4.3.17' })
  assert.equal(ok, false)
})

test('S7-17b: verifyCrlSignature throws E24 on wrong-size publicKey (key from another param set)', async () => {
  const crl = parseCrl(buildCrl())
  const { ml_dsa44 } = await import('@noble/post-quantum/ml-dsa.js')
  const kp = ml_dsa44.keygen() // 1312-byte key vs 1952 expected for mldsa65
  assert.throws(
    () => verifyCrlSignature(crl, { publicKey: kp.publicKey, algorithmOid: '2.16.840.1.101.3.4.3.17' }),
    (e) => e.code === 'E24',
  )
})

test('S7-18: verifyCrlSignature returns false for valid key, bad signature', async () => {
  const crl = parseCrl(buildCrl())
  const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js')
  const kp = ml_dsa65.keygen()
  const ok = verifyCrlSignature(crl, { publicKey: kp.publicKey, algorithmOid: '2.16.840.1.101.3.4.3.17' })
  assert.equal(ok, false)
})

// ─────────────────────────────────────────────────────────────
// S7-corpus: real corpus certs remain parseable
// ─────────────────────────────────────────────────────────────
test('S7-19: corpus leaf1/root are unaffected by CRL parsing', () => {
  const leaf = readFileSync(join(corpus, 'leaf1.der'))
  // unrelated regression: CRL parser must not touch cert corpus
  assert.throws(() => parseCrl(leaf), (e) => e.code === 'E24')
})

test('S7-20: verifyCrlSignature rejects malformed publicKey bytes', () => {
  const crl = parseCrl(buildCrl())
  assert.throws(
    () => verifyCrlSignature(crl, { publicKey: new Uint8Array(5), algorithmOid: '2.16.840.1.101.3.4.3.17' }),
    TypeError,
  )
})
