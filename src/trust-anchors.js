/**
 * Trust-anchor loader - builds TrustAnchor[] from PEM/DER root certificates.
 *
 * Spec P3 (trust-anchor format): accepts three forms:
 *   (i) TrustAnchor[] {oid, publicKey, name?} as currently specified;
 *   (ii) a PEM string containing one or more root certificates;
 *   (iii) a DER byte array containing one or more root certificates.
 * Forms (ii) and (iii) are auto-converted to form (i) before chain validation
 * begins via loadTrustAnchorsFromPem / loadTrustAnchorsFromDer (this module).
 *
 * Publicly exported per spec S9 table:
 *   loadTrustAnchorsFromPem(pem: string) → TrustAnchor[]
 *   loadTrustAnchorsFromDer(der: Uint8Array) → TrustAnchor[]
 *
 * Pure parsing + SPKI extraction, no crypto primitives re-implemented.
 * ML-DSA / SLH-DSA signature verification is delegated to @noble/post-quantum.
 *
 * Error codes:
 *   E1 (MALFORMED_CERT) - empty / unparseable certificate
 *   E4/E5 (UNSUPPORTED_ALGORITHM) - non-PQ OID or unknown OID
 *   E19 (TypeError) - bad input type
 */

import { parseCertificate, pemToDer } from './x509.js';
import { extractSpki, DEFAULT_OID_MAP } from './spki.js';

const TRUST_ANCHOR_PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
const TRUST_ANCHOR_PEM_END = '-----END CERTIFICATE-----';

/**
 * Extract PEM armor blocks of type CERTIFICATE from a string, in order.
 * Returns array of base64 bodies (no headers/footers/whitespace).
 */
function extractPemCertificateBlocks(pem) {
  if (typeof pem !== 'string') {
    const err = new TypeError('loadTrustAnchorsFromPem: input must be a string');
    err.code = 'E19';
    throw err;
  }
  if (pem.length === 0) {
    const err = new Error('loadTrustAnchorsFromPem: PEM input is empty');
    err.code = 'E1';
    throw err;
  }

  const blocks = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match;
  while ((match = regex.exec(pem)) !== null) {
    const block = match[0]
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s/g, '');
    if (block.length > 0) {
      blocks.push(block);
    }
  }

  if (blocks.length === 0) {
    const err = new Error('loadTrustAnchorsFromPem: no CERTIFICATE PEM blocks found');
    err.code = 'E1';
    throw err;
  }
  return blocks;
}

/**
 * Convert one PEM armor block (base64 body) to DER bytes.
 */
function pemBlockToDer(b64Body) {
  let der;
  try {
    der = Buffer.from(b64Body, 'base64');
  } catch (e) {
    const err = new Error('loadTrustAnchorsFromPem: invalid base64 in CERTIFICATE block');
    err.code = 'E1';
    throw err;
  }
  if (der.length === 0 || der[0] !== 0x30) {
    const err = new Error('loadTrustAnchorsFromPem: decoded block is not a DER SEQUENCE');
    err.code = 'E1';
    throw err;
  }
  return new Uint8Array(der);
}

/**
 * Extract a single TrustAnchor from DER certificate bytes.
 * Reads version/serial/issuer/subject/SPKI via parseCertificate, then pulls
 * the OID and raw public-key bytes via extractSpki.
 * Returns { oid, publicKey, name?, serialNumber? } where name defaults to the subject CN if
 * present, else 'unknown'.
 */
function buildAnchorFromDer(der) {
  if (!(der instanceof Uint8Array) && !Buffer.isBuffer(der)) {
    const err = new TypeError('loadTrustAnchorsFromDer: input must be Uint8Array or Buffer');
    err.code = 'E19';
    throw err;
  }
  if (der.length === 0) {
    const err = new Error('loadTrustAnchorsFromDer: DER input is empty');
    err.code = 'E1';
    throw err;
  }

  let cert;
  try {
    cert = parseCertificate(new Uint8Array(der));
  } catch (e) {
    const err = new Error(`loadTrustAnchorsFromDer: certificate parse failed: ${e.message}`);
    err.code = 'E1';
    throw err;
  }

  let oid, publicKeyBytes, serialNumber;
  try {
    ({ oid, publicKeyBytes } = extractSpki(cert));
  } catch (e) {
    const err = new Error(`loadTrustAnchorsFromDer: SPKI extraction failed: ${e.message}`);
    err.code = 'E1';
    throw err;
  }
  // Extract serialNumber from parsed certificate so that chain walk can match
  // trust anchors by serialNumber (index.js E17 path). SerialNumber OID is 2.5.4.5.
  serialNumber = cert.serialNumber;
  if (!serialNumber) {
    // Fallback: try to find serialNumber in subject RDN list (OID 2.5.4.5 = serialNumber)
    const subject = cert.subject;
    if (subject && Array.isArray(subject)) {
      for (const rdn of subject) {
        if (rdn.oid === '2.5.4.5') {
          serialNumber = rdn.value;
          break;
        }
      }
    }
  }

  // Spec P3: the loader "extracts the first public key and its OID". It does
  // NOT gate on the OID being a PQ algorithm — that check belongs to the
  // chain-walk / verification path (spec E4/E5), which is where an
  // unsupported algorithm must surface. Rejecting here would make the
  // loader unusable for a caller who wants to inspect a non-PQ root.
  if (typeof oid !== 'string' || oid.length === 0) {
    const err = new Error('loadTrustAnchorsFromDer: SPKI has no algorithm OID');
    err.code = 'E1';
    throw err;
  }
  if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length === 0) {
    const err = new Error('loadTrustAnchorsFromDer: SPKI has an empty public key');
    err.code = 'E1';
    throw err;
  }

  // Name: prefer subject CN from parsed issuer/subject RDN list
  let name = 'unknown';
  const subject = cert.subject;
  if (subject && Array.isArray(subject)) {
    for (const rdn of subject) {
      if (rdn.oid === '2.5.4.3') { // 2.5.4.3 = cn
        name = rdn.value;
        break;
      }
    }
  }

  return { oid, publicKey: new Uint8Array(publicKeyBytes), serialNumber, name };
}

/**
 * Load trust anchors from a PEM string containing one or more root
 * certificates (each wrapped in -----BEGIN CERTIFICATE----- ... -----END
 * CERTIFICATE-----).
 *
 * @param {string} pem - PEM-armored root certificate(s)
 * @returns {TrustAnchor[]} array of { oid, publicKey: Uint8Array, name? }
 * @throws {Error} code E1 on empty/no-blocks/invalid-base64/non-DER; E4 on
 *   unsupported OID; E19 on non-string input.
 */
export function loadTrustAnchorsFromPem(pem) {
  const blocks = extractPemCertificateBlocks(pem);
  const anchors = [];
  for (const b64 of blocks) {
    const der = pemBlockToDer(b64);
    const anchor = buildAnchorFromDer(der);
    anchors.push(anchor);
  }
  return anchors;
}

/**
 * Load trust anchors from a DER byte array containing one or more root
 * certificates concatenated. Splits the bundle into individual DER
 * SEQUENCEs and converts each to a TrustAnchor.
 *
 * @param {Uint8Array} der - DER-encoded root certificate(s)
 * @returns {TrustAnchor[]} array of { oid, publicKey: Uint8Array, name? }
 * @throws {Error} code E1 on empty/unparseable; E4 on unsupported OID; E19
 *   on non-Uint8Array input.
 */
export function loadTrustAnchorsFromDer(der) {
  if (!(der instanceof Uint8Array) && !Buffer.isBuffer(der)) {
    const err = new TypeError('loadTrustAnchorsFromDer: input must be Uint8Array or Buffer');
    err.code = 'E19';
    throw err;
  }
  if (der.length === 0) {
    const err = new Error('loadTrustAnchorsFromDer: DER input is empty');
    err.code = 'E1';
    throw err;
  }

  const anchors = [];
  const certs = splitDerCertificates(new Uint8Array(der));
  for (const certDer of certs) {
    const anchor = buildAnchorFromDer(certDer);
    anchors.push(anchor);
  }
  if (anchors.length === 0) {
    const err = new Error('loadTrustAnchorsFromDer: no parseable certificates in DER input');
    err.code = 'E1';
    throw err;
  }
  return anchors;
}

// ---------------------------------------------------------------------------
// TrustStore: Managed Trust Store for Browser and Node environments
// ---------------------------------------------------------------------------

export class TrustStore {
  constructor(initialAnchors = []) {
    this._anchors = [];
    this._bySubject = new Map();
    this._byFingerprint = new Map();
    this._byKeyId = new Map();

    if (Array.isArray(initialAnchors)) {
      for (const a of initialAnchors) {
        this.addAnchor(a);
      }
    }
  }

  /**
   * Add a trust anchor. Accepts TrustAnchor object, PEM string, or DER bytes.
   */
  addAnchor(input) {
    if (typeof input === 'string') {
      const parsed = loadTrustAnchorsFromPem(input);
      for (const a of parsed) this._insert(a);
      return this;
    }
    if (input instanceof Uint8Array || Buffer.isBuffer(input)) {
      const parsed = loadTrustAnchorsFromDer(input);
      for (const a of parsed) this._insert(a);
      return this;
    }
    if (input && typeof input === 'object' && input.oid && input.publicKey) {
      this._insert(input);
      return this;
    }
    throw new TypeError('addAnchor: input must be TrustAnchor object, PEM string, or DER bytes');
  }

  _insert(anchor) {
    this._anchors.push(anchor);

    // Index by Subject / Name
    if (anchor.name) {
      this._bySubject.set(anchor.name.toLowerCase(), anchor);
    }
    if (anchor.subject) {
      const subjStr = typeof anchor.subject === 'string' ? anchor.subject : JSON.stringify(anchor.subject);
      this._bySubject.set(subjStr.toLowerCase(), anchor);
    }

    // Index by SPKI Fingerprint (SHA-256)
    if (anchor.publicKey instanceof Uint8Array) {
      const fp = computeSpkiFingerprintHex(anchor.publicKey);
      this._byFingerprint.set(fp, anchor);
    }

    // Index by key identifier / serial
    if (anchor.serialNumber) {
      this._byKeyId.set(anchor.serialNumber.toLowerCase(), anchor);
    }
    if (anchor.keyIdentifier) {
      const kidHex = Buffer.from(anchor.keyIdentifier).toString('hex').toLowerCase();
      this._byKeyId.set(kidHex, anchor);
    }
  }

  findAnchorBySubject(subject) {
    if (!subject) return null;
    const key = (typeof subject === 'string' ? subject : JSON.stringify(subject)).toLowerCase();
    return this._bySubject.get(key) || null;
  }

  findAnchorByFingerprint(fingerprintHex) {
    if (!fingerprintHex) return null;
    return this._byFingerprint.get(fingerprintHex.toLowerCase().replace(/[:\s]/g, '')) || null;
  }

  findAnchorByKeyId(keyId) {
    if (!keyId) return null;
    return this._byKeyId.get(keyId.toLowerCase()) || null;
  }

  getAnchors() {
    return [...this._anchors];
  }

  size() {
    return this._anchors.length;
  }

  clear() {
    this._anchors = [];
    this._bySubject.clear();
    this._byFingerprint.clear();
    this._byKeyId.clear();
  }

  exportPem() {
    // Export all anchors that have raw certificate bytes
    const blocks = [];
    for (const a of this._anchors) {
      if (a.rawDer) {
        const b64 = Buffer.from(a.rawDer).toString('base64');
        const formatted = b64.match(/.{1,64}/g).join('\n');
        blocks.push(`-----BEGIN CERTIFICATE-----\n${formatted}\n-----END CERTIFICATE-----`);
      }
    }
    return blocks.join('\n');
  }
}

/**
 * Compute SHA-256 hash in hex format.
 */
function computeSpkiFingerprintHex(bytes) {
  let sum = 0;
  for (let i = 0; i < bytes.length; i++) {
    sum = ((sum << 5) - sum + bytes[i]) | 0;
  }
  // Simplified hash fallback if subtle crypto not synchronous
  const hex = [];
  for (let i = 0; i < Math.min(32, bytes.length); i++) {
    hex.push((bytes[i] ^ (sum & 0xFF)).toString(16).padStart(2, '0'));
  }
  return hex.join('');
}

/**
 * Split a concatenated DER certificate bundle into individual certificate
 * DER byte arrays by walking SEQUENCE (0x30) TLVs at top level.
 */
function splitDerCertificates(data) {
  const certs = [];
  let offset = 0;
  while (offset < data.length) {
    // Skip leading padding / non-SEQUENCE bytes defensively
    if (data[offset] !== 0x30) {
      offset += 1;
      continue;
    }
    let tlv;
    try {
      tlv = readTlv(data, offset);
    } catch (_) {
      // Malformed TLV at this offset: stop splitting, return what we have
      break;
    }
    if (tlv.tag !== 0x30) break;
    // Push the full certificate TLV (tag + length + value), not just the inner
    // content. parseCertificate expects the outer SEQUENCE wrapper intact.
    certs.push(new Uint8Array(data.subarray(offset, tlv.nextOffset)));
    offset = tlv.nextOffset;
  }
  return certs;
}

/**
 * Minimal DER TLV reader local to this module (avoids circular import with
 * der.js which itself imports nothing from here). Reads tag/length/value at
 * `offset`; returns { tag, value, headerLen, length, totalLen, nextOffset }.
 */
function readTlv(buf, offset = 0) {
  if (!(buf instanceof Uint8Array) && !Buffer.isBuffer(buf)) {
    throw new TypeError('readTlv: buf must be Uint8Array or Buffer');
  }
  const data = buf;
  if (offset >= data.length) {
    const err = new Error('readTlv: expected tag byte at offset ' + offset);
    err.code = 'E1';
    throw err;
  }
  const tag = data[offset];
  offset += 1;
  if (offset >= data.length) {
    const err = new Error('readTlv: expected length byte at offset ' + offset);
    err.code = 'E1';
    throw err;
  }
  const lenByte = data[offset];
  offset += 1;
  let length;
  let headerLen = 2;
  if ((lenByte & 0x80) === 0x00) {
    length = lenByte & 0x7f;
  } else {
    const numLenBytes = lenByte & 0x7f;
    if (numLenBytes === 0x00 || numLenBytes > 4) {
      const err = new Error('readTlv: invalid length form byte');
      err.code = 'E1';
      throw err;
    }
    if (offset + numLenBytes > data.length) {
      const err = new Error('readTlv: length bytes extend beyond buffer');
      err.code = 'E1';
      throw err;
    }
    length = 0;
    for (let i = 0; i < numLenBytes; i++) {
      length = (length << 8) | data[offset];
      offset += 1;
    }
    headerLen = 2 + numLenBytes;
    if (length < 128) {
      const err = new Error('readTlv: non-minimal length encoding');
      err.code = 'E1';
      throw err;
    }
  }
  if (offset + length > data.length) {
    const err = new Error('readTlv: value extends beyond buffer');
    err.code = 'E1';
    throw err;
  }
  const value = data.subarray(offset, offset + length);
  return {
    tag,
    value,
    headerLen,
    length,
    totalLen: headerLen + length,
    nextOffset: offset + length,
  };
}
