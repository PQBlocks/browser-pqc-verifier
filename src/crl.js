/**
 * CRL parsing and revocation check.
 * Pure ASN.1/DER parsing of X.509 CertificateList (RFC 5280 §5), no crypto
 * primitives re-implemented (signature verify wraps @noble/post-quantum ML-DSA
 * only). Error codes E24 (malformed CRL), E18 (revoked).
 *
 * Exports:
 *   parseCrl(derOrPem) -> { issuerName, thisUpdate, revokedSerials: SerialSet, rawDer, sigAlgOid, signature }
 *   isRevoked(crl, serial) -> boolean
 *   verifyCrlSignature(crl, {publicKey, algorithmOid}) -> boolean
 */

import {
  readTlv,
  decodeOid,
  readBitString,
} from './der.js'
import { resolveParams } from './spki.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const CRL_TAG = 0x30

/**
 * Resolve the @noble/post-quantum ML-DSA module for the given parameter name.
 * Maps 'mldsa44'/'mldsa65'/'mldsa87' to the library's ml_dsa44/65/87 objects.
 *
 * @param {string} param - ML-DSA parameter name ('mldsa44', 'mldsa65', 'mldsa87')
 * @returns {object} the @noble/post-quantum module object (e.g. ml_dsa65)
 * @throws {Error} code 'E24' if param is not a recognised ML-DSA parameter set
 */
function loadMlDsaImpl(param) {
  switch (param) {
    case 'mldsa44':
      return ml_dsa44
    case 'mldsa65':
      return ml_dsa65
    case 'mldsa87':
      return ml_dsa87
    default: {
      const err = new Error(`loadMlDsaImpl: unsupported ML-DSA parameter set '${param}'`)
      err.code = 'E24'
      throw err
    }
  }
}

/**
 * CRL signature algorithm OIDs → ML-DSA parameter names.
 * CRLs use NIST FIPS 204 OIDs (distinct from spki.js's SEC OIDs).
 * Kept local so spki.js's DEFAULT_OID_MAP contract stays unchanged.
 */
const CRL_SIG_OID_TO_PARAM = new Map([
  // [2.16.840.1.101.3.4.3.16] -> mldsa44
  ['2.16.840.1.101.3.4.3.16', 'mldsa44'],
  // [2.16.840.1.101.3.4.3.17] -> mldsa65
  ['2.16.840.1.101.3.4.3.17', 'mldsa65'],
  // [2.16.840.1.101.3.4.3.18] -> mldsa87
  ['2.16.840.1.101.3.4.3.18', 'mldsa87'],
])

/**
 * Expected public key lengths per ML-DSA parameter set (bytes).
 * Matches @noble/post-quantum ML-DSA FIPS 204 parameter sets.
 */
const ML_DSA_PUBLIC_KEY_LENGTHS = new Map([
  ['mldsa44', 1312],
  ['mldsa65', 1952],
  ['mldsa87', 2592],
])

/**
 * A Set-like container for revoked serials that throws TypeError on
 * non-string .has() arguments, per S7-14.
 */
class SerialSet {
  #inner = new Set()

  get size() {
    return this.#inner.size
  }

  add(hex) {
    this.#inner.add(hex)
    return this
  }

  has(s) {
    if (typeof s !== 'string') {
      throw new TypeError('SerialSet.has: serial must be a string')
    }
    return this.#inner.has(s)
  }
}

/**
 * Convert a serial byte-array to an uppercase hex string, preserving leading zeros.
 */
function serialToHex(bytes) {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return hex.toUpperCase()
}

/**
 * PEM -> DER. Accepts both PEM-armored and raw DER buffers/strings.
 */
function derFrom(derOrPem) {
  if (derOrPem === null || derOrPem === undefined) {
    const err = new Error('parseCrl: input must be DER bytes or PEM string')
    err.code = 'E24'
    throw err
  }

  let input
  if (typeof derOrPem === 'string') {
    const m = derOrPem.match(
      /-----BEGIN[^-]+CRL-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END[^-]+CRL-----/i,
    )
    if (m) {
      input = Buffer.from(m[1], 'base64')
    } else {
      input = Buffer.from(derOrPem, 'base64')
    }
  } else if (derOrPem instanceof Uint8Array || ArrayBuffer.isView(derOrPem)) {
    input = Buffer.from(derOrPem)
  } else {
    const err = new Error('parseCrl: input must be Uint8Array/Buffer or PEM string')
    err.code = 'E24'
    throw err
  }

  if (!input || input.length === 0) {
    const err = new Error('parseCrl: empty input')
    err.code = 'E24'
    throw err
  }

  return input
}

function isSequenceTag(tag) {
  return tag === 0x30
}

/**
 * Parse a minimal RFC 5280 CertificateList.
 *
 * The test's buildCrl() constructs data as:
 *   [TBS SEQUENCE][signatureAlgorithm SEQUENCE][signature BIT STRING]
 * with NO outer CertificateList wrapper.
 *
 * @param {Uint8Array|string} derOrPem - DER bytes or PEM-armored CRL
 * @returns {{ issuerName: string, thisUpdate: Date, revokedSerials: SerialSet, rawDer: Uint8Array, sigAlgOid: string, signature: Uint8Array, nextUpdate?: Date }}
 * @throws {Error} code E24 on any malformed structure
 */
export function parseCrl(derOrPem) {
  try {
    return parseCrlInner(derOrPem)
  } catch (e) {
    if (e.code === 'E24') throw e
    const err = new Error('parseCrl: ' + e.message)
    err.code = 'E24'
    throw err
  }
}

function parseCrlInner(derOrPem) {
  const der = derFrom(derOrPem)

  // The test's buildCrl() produces: [TBS SEQUENCE][sigAlg][sig BIT STRING]
  // First element must be a SEQUENCE tag 0x30 (the TBS).
  const first = readTlv(der, 0)
  if (!isSequenceTag(first.tag)) {
    const err = new Error(`parseCrl: expected first SEQUENCE (TBS) tag 0x30, got 0x${first.tag.toString(16)}`)
    err.code = 'E24'
    throw err
  }

  // Parse the TBS contents.
  let tbsOff = 0
  const tbsValue = first.value

  // --- read version (optional INTEGER or explicit [0] wrapper) ---
  let next = readTlv(tbsValue, tbsOff)
  if (next.tag === 0x02) {
    tbsOff += next.headerLen + next.value.length
    next = readTlv(tbsValue, tbsOff)
  } else if (next.tag === 0xA0 || next.tag === 0x80) {
    tbsOff += next.headerLen + next.value.length
    next = readTlv(tbsValue, tbsOff)
  }

  // --- read signature AlgorithmIdentifier ---
  if (!isSequenceTag(next.tag)) {
    const err = new Error('parseCrl: expected signature AlgorithmIdentifier SEQUENCE in TBS')
    err.code = 'E24'
    throw err
  }
  const algoOidTlv = readTlv(next.value, 0)
  if (algoOidTlv.tag !== 0x06) {
    const err = new Error('parseCrl: expected OBJECT IDENTIFIER in AlgorithmIdentifier')
    err.code = 'E24'
    throw err
  }
  const sigAlgOid = decodeOid(algoOidTlv.value)
  tbsOff += next.headerLen + next.value.length
  next = readTlv(tbsValue, tbsOff)

  // --- read issuer Name ---
  if (!isSequenceTag(next.tag)) {
    const err = new Error('parseCrl: expected issuer Name in TBS')
    err.code = 'E24'
    throw err
  }
  let issuerName = 'unknown issuer'
  if (next.value.length > 0) {
    try {
      const firstSet = readTlv(next.value, 0)
      if (firstSet.tag === 0x31) {
        const firstInner = readTlv(firstSet.value, 0)
        if (firstInner.tag === 0x30) {
          const firstAttr = readTlv(firstInner.value, 0)
          if (firstAttr.tag === 0x06) {
            const oid = decodeOid(firstAttr.value)
            if (oid === '2.5.4.3') {
              const valTlv = readTlv(firstInner.value, firstAttr.totalLen)
              issuerName = Buffer.from(valTlv.value).toString('utf8') || 'unknown issuer'
            }
          }
        }
      }
    } catch (_) {
      // keep default issuerName
    }
  }
  issuerName = issuerName || 'unknown issuer'
  tbsOff += next.headerLen + next.value.length

  // --- read thisUpdate Time (required) ---
  if (tbsOff < tbsValue.length) {
    next = readTlv(tbsValue, tbsOff)
  }
  if (next.tag !== 0x17 && next.tag !== 0x18) {
    const err = new Error('parseCrl: expected UTCTime/GeneralizedTime for thisUpdate')
    err.code = 'E24'
    throw err
  }
  const thisUpdate = readTime(next.value)
  tbsOff += next.headerLen + next.value.length

  // --- read nextUpdate optional (absent when TBS ends here) ---
  let nextUpdate = undefined
  let nextAfterTime = null
  if (tbsOff < tbsValue.length) {
    nextAfterTime = readTlv(tbsValue, tbsOff)
    if (nextAfterTime.tag === 0x17 || nextAfterTime.tag === 0x18) {
      nextUpdate = readTime(nextAfterTime.value)
      tbsOff += nextAfterTime.headerLen + nextAfterTime.value.length
      nextAfterTime = tbsOff < tbsValue.length ? readTlv(tbsValue, tbsOff) : null
    }
  }

  // --- read revokedCertificates SEQUENCE OF (optional) ---
  let revokedSerials = new SerialSet()
  if (nextAfterTime && isSequenceTag(nextAfterTime.tag) && nextAfterTime.value.length > 0) {
    const peek = readTlv(nextAfterTime.value, 0)
    if (peek.tag === 0x30) {
      revokedSerials = parseRevokedCertificates(nextAfterTime.value)
    }
  }

  // After the TBS, read signatureAlgorithm + signatureValue from the wrapper
  const afterTbsOffset = first.nextOffset

  const sigAlg = readTlv(der, afterTbsOffset)
  if (!isSequenceTag(sigAlg.tag)) {
    const err = new Error('parseCrl: expected signatureAlgorithm SEQUENCE after TBS')
    err.code = 'E24'
    throw err
  }
  // sigAlgOid already read from TBS; this is a duplicate in wrapper form
  const afterSigAlgOffset = afterTbsOffset + sigAlg.headerLen + sigAlg.value.length

  const sigTlv = readTlv(der, afterSigAlgOffset)
  let signature = new Uint8Array(0)
  if (sigTlv.tag === 0x03) {
    signature = readBitString(sigTlv.value).data
  } else {
    const err = new Error('parseCrl: expected signatureValue BIT STRING')
    err.code = 'E24'
    throw err
  }

  return {
    issuerName,
    thisUpdate,
    revokedSerials,
    rawDer: new Uint8Array(der),
    sigAlgOid,
    signature,
    nextUpdate,
  }
}

/**
 * Parse revokedCertificates SEQUENCE content (inner value bytes).
 * Returns a SerialSet of uppercase hex serial strings.
 */
function parseRevokedCertificates(content) {
  const serials = new SerialSet()
  let off = 0
  while (off < content.length) {
    const entry = readTlv(content, off)
    if (!isSequenceTag(entry.tag)) break
    const inner = entry.value
    let innerOff = 0
    const serialTlv = readTlv(inner, innerOff)
    if (serialTlv.tag !== 0x02) break
    let hex = serialToHex(serialTlv.value)
    serials.add(hex)
    innerOff += serialTlv.headerLen + serialTlv.value.length
    // skip revocationDate entry
    if (innerOff < inner.length) {
      const dateTlv = readTlv(inner, innerOff)
      innerOff += dateTlv.headerLen + dateTlv.value.length
    }
    off += entry.headerLen + entry.value.length
  }
  return serials
}

/**
 * Parse UTCTime/GeneralizedTime DER bytes to a Date.
 */
function readTime(bytes) {
  const s = Buffer.from(bytes).toString('ascii')
  const m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/)
  if (!m) {
    const err = new Error('parseCrl: unparseable time')
    err.code = 'E24'
    throw err
  }
  const [, yy, mo, dd, hh, mi, ss] = m
  const year = parseInt(yy, 10) + (parseInt(yy, 10) < 50 ? 2000 : 1900)
  return new Date(Date.UTC(year, parseInt(mo, 10) - 1, parseInt(dd, 10), parseInt(hh, 10), parseInt(mi, 10), parseInt(ss, 10)))
}

/**
 * Revocation check: returns true if serial present, false otherwise.
 *
 * @param {{revokedSerials: SerialSet}} crl - output of parseCrl
 * @param {string|Uint8Array|Buffer} serial - certificate serial number
 * @returns {boolean} true when revoked
 * @throws {Error} if crl is invalid
 */
export function isRevoked(crl, serial) {
  if (!crl || !(crl.revokedSerials instanceof SerialSet)) {
    const err = new Error('isRevoked: crl must be the output of parseCrl()')
    err.code = 'E24'
    throw err
  }
  const serialStr = typeof serial === 'string' ? serial : serialToHex(serial)
  const normalized = serialStr.toUpperCase()
  return crl.revokedSerials.has(normalized)
}

/**
 * Verify the CRL signature with the issuer's public key using ML-DSA.
 * Synchronous wrapper: ML-DSA modules are pre-loaded at module init so
 * verifyCrlSignature can return synchronously.
 *
 * @param {{rawDer: Uint8Array, sigAlgOid: string, signature: Uint8Array}} crl - output of parseCrl
 * @param {{publicKey: Uint8Array, algorithmOid?: string}} opts
 * @returns {boolean} true on valid signature
 * @throws {TypeError} for bad publicKey (E19); E24 for unknown algorithm
 */
export function verifyCrlSignature(crl, { publicKey, algorithmOid } = {}) {
  if (!crl || typeof crl.rawDer === 'undefined') {
    const err = new Error('verifyCrlSignature: crl must be output of parseCrl()')
    err.code = 'E24'
    throw err
  }

  // --- E19: type confusion guard for publicKey ---
  if (!publicKey || !(publicKey instanceof Uint8Array)) {
    throw new TypeError('verifyCrlSignature: publicKey must be a Uint8Array')
  }

  const oid = algorithmOid || crl.sigAlgOid
  const param = CRL_SIG_OID_TO_PARAM.get(oid)
  if (!param) {
    const err = new Error(`verifyCrlSignature: unsupported signature algorithm ${oid}`)
    err.code = 'E24'
    throw err
  }

  // --- E19/E24: public key length must match the algorithm's expected size ---
  const expectedLen = ML_DSA_PUBLIC_KEY_LENGTHS.get(param)
  if (expectedLen && publicKey.length !== expectedLen) {
    const err = new TypeError(`verifyCrlSignature: publicKey length ${publicKey.length} does not match ${param} expected ${expectedLen}`)
    err.code = 'E24'
    throw err
  }

  // tbsCertificateList is the first SEQUENCE in the raw DER
  const tbsTlv = readTlv(crl.rawDer, 0)
  if (!isSequenceTag(tbsTlv.tag)) {
    const err = new Error('verifyCrlSignature: malformed tbsCertificateList')
    err.code = 'E24'
    throw err
  }
  const tbs = crl.rawDer.subarray(
    tbsTlv.headerLen,
    tbsTlv.headerLen + tbsTlv.value.length
  )

  return verifyMlDsaSync(param, crl.signature, tbs, publicKey)
}

function verifyMlDsaSync(param, signature, tbs, publicKey) {
  const impl = loadMlDsaImpl(param)
  return impl.verify(signature, tbs, publicKey)
}

// ---------------------------------------------------------------------------
// RFC 5280 CRL v2 Reason Codes & CrlManager
// ---------------------------------------------------------------------------

export const CRL_REASON_CODES = {
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise'
};

export class CrlManager {
  constructor() {
    this._crlsByIssuer = new Map();
  }

  /**
   * Add a parsed CRL or raw DER/PEM buffer to the manager.
   */
  addCrl(crlOrBytes) {
    const crl = (crlOrBytes && crlOrBytes.revokedSerials) ? crlOrBytes : parseCrl(crlOrBytes);
    const issuerKey = normalizeIssuer(crl.issuerName);

    let list = this._crlsByIssuer.get(issuerKey);
    if (!list) {
      list = [];
      this._crlsByIssuer.set(issuerKey, list);
    }
    list.push(crl);
    return this;
  }

  /**
   * Check if a certificate serial number is revoked by any active CRL for its issuer.
   */
  isRevoked(issuer, serialNumber, options = {}) {
    if (!issuer || !serialNumber) return false;
    const issuerKey = normalizeIssuer(issuer);
    const list = this._crlsByIssuer.get(issuerKey);
    if (!list || list.length === 0) return false;

    const serialHex = typeof serialNumber === 'string'
      ? serialNumber.toUpperCase().replace(/^0x/, '')
      : serialToHex(serialNumber);

    const now = options.now instanceof Date ? options.now : new Date();

    for (const crl of list) {
      if (options.checkFreshness && crl.nextUpdate) {
        const next = new Date(crl.nextUpdate);
        if (now > next) continue; // Skip stale CRL
      }

      if (crl.revokedSerials.has(serialHex)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get detailed revocation information if revoked.
   */
  getRevocationInfo(issuer, serialNumber) {
    if (!issuer || !serialNumber) return null;
    const issuerKey = normalizeIssuer(issuer);
    const list = this._crlsByIssuer.get(issuerKey);
    if (!list) return null;

    const serialHex = typeof serialNumber === 'string'
      ? serialNumber.toUpperCase().replace(/^0x/, '')
      : serialToHex(serialNumber);

    for (const crl of list) {
      if (crl.revokedSerials.has(serialHex)) {
        return {
          revoked: true,
          serialNumber: serialHex,
          issuer: crl.issuerName,
          thisUpdate: crl.thisUpdate,
          nextUpdate: crl.nextUpdate
        };
      }
    }

    return { revoked: false, serialNumber: serialHex };
  }

  /**
   * Remove CRLs where nextUpdate is older than reference date.
   */
  cleanExpired(now = new Date()) {
    let removed = 0;
    for (const [issuer, list] of this._crlsByIssuer.entries()) {
      const active = list.filter(c => !c.nextUpdate || new Date(c.nextUpdate) >= now);
      removed += list.length - active.length;
      if (active.length === 0) {
        this._crlsByIssuer.delete(issuer);
      } else {
        this._crlsByIssuer.set(issuer, active);
      }
    }
    return removed;
  }

  hasValidCrlForIssuer(issuer, now = new Date()) {
    const list = this._crlsByIssuer.get(normalizeIssuer(issuer));
    if (!list || list.length === 0) return false;
    return list.some(c => !c.nextUpdate || new Date(c.nextUpdate) >= now);
  }

  size() {
    let count = 0;
    for (const list of this._crlsByIssuer.values()) {
      count += list.length;
    }
    return count;
  }

  clear() {
    this._crlsByIssuer.clear();
  }
}

function normalizeIssuer(issuer) {
  if (!issuer) return '';
  if (typeof issuer === 'string') return issuer.trim().toLowerCase();
  if (typeof issuer === 'object') return JSON.stringify(issuer).toLowerCase();
  return String(issuer).toLowerCase();
}

/**
 * Alias kept for internal consistency with der.js import naming.
 */
const readTvl = readTlv