import { readTlv, decodeOid } from './der.js';

export const CMS_OIDS = {
  DATA: '1.2.840.113549.1.7.1',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  ENVELOPED_DATA: '1.2.840.113549.1.7.3',
  SIGNED_AND_ENVELOPED_DATA: '1.2.840.113549.1.7.4',
  DIGESTED_DATA: '1.2.840.113549.1.7.5',
  ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
  AUTH_DATA: '1.2.840.113549.1.9.16.1.2'
};

/**
 * Parse a DER-encoded PKCS#7 / CMS ContentInfo structure.
 * @param {Uint8Array} der - Raw DER bytes
 * @returns {Object} - Parsed CMS ContentInfo
 */
export function parseCmsContentInfo(der) {
  if (!(der instanceof Uint8Array) && !Buffer.isBuffer(der)) {
    throw new TypeError('parseCmsContentInfo: der must be Uint8Array or Buffer');
  }

  const outer = readTlv(der, 0);
  if (outer.tag !== 0x30) {
    throw new Error('MALFORMED_CERT: expected ContentInfo SEQUENCE');
  }

  let pos = 0;
  const contentInfoData = outer.value;

  // 1. ContentType OID
  const contentTypeTlv = readTlv(contentInfoData, pos);
  if (contentTypeTlv.tag !== 0x06) {
    throw new Error('MALFORMED_CERT: expected contentType OID in ContentInfo');
  }
  const contentType = decodeOid(contentTypeTlv.value);
  pos += contentTypeTlv.totalLen;

  // 2. Content [0] EXPLICIT
  let content = null;
  if (pos < contentInfoData.length) {
    const contentTlv = readTlv(contentInfoData, pos);
    if ((contentTlv.tag & 0xC0) === 0x80) { // Context-specific [0]
      content = contentTlv.value;
    }
  }

  return {
    contentType,
    content
  };
}

/**
 * Extract all certificates from a CMS / PKCS#7 SignedData structure.
 * @param {Uint8Array} signedDataBytes - Raw bytes of SignedData or outer ContentInfo
 * @returns {Uint8Array[]} - Array of DER-encoded certificate byte buffers
 */
export function extractCmsCertificates(signedDataBytes) {
  if (!signedDataBytes || signedDataBytes.length === 0) return [];

  let content = signedDataBytes;
  try {
    const ci = parseCmsContentInfo(signedDataBytes);
    if (ci.contentType === CMS_OIDS.SIGNED_DATA && ci.content) {
      content = ci.content;
    }
  } catch {
    // If not outer ContentInfo, attempt parsing directly as SignedData
  }

  const outer = readTlv(content, 0);
  if (outer.tag !== 0x30) return [];

  let pos = 0;
  const val = outer.value;

  // version (INTEGER)
  const verTlv = readTlv(val, pos);
  pos += verTlv.totalLen;

  // digestAlgorithms (SET OF DigestAlgorithmIdentifier)
  const digestAlgsTlv = readTlv(val, pos);
  pos += digestAlgsTlv.totalLen;

  // encapContentInfo (SEQUENCE)
  const encapContentTlv = readTlv(val, pos);
  pos += encapContentTlv.totalLen;

  const certs = [];

  // certificates [0] IMPLICIT CertificateSet OPTIONAL
  if (pos < val.length) {
    const next = readTlv(val, pos);
    if (next.tag === 0xA0) { // [0] IMPLICIT SET OF / SEQUENCE OF
      let certPos = 0;
      const certSet = next.value;
      while (certPos < certSet.length) {
        if (certSet[certPos] !== 0x30) {
          certPos++;
          continue;
        }
        const certTlv = readTlv(certSet, certPos);
        certs.push(new Uint8Array(certTlv.raw || certSet.subarray(certPos, certPos + certTlv.totalLen)));
        certPos += certTlv.totalLen;
      }
    }
  }

  return certs;
}

/**
 * Extract all CRLs from a CMS / PKCS#7 SignedData structure.
 * @param {Uint8Array} signedDataBytes - Raw bytes
 * @returns {Uint8Array[]} - Array of DER-encoded CRL byte buffers
 */
export function extractCmsCrls(signedDataBytes) {
  if (!signedDataBytes || signedDataBytes.length === 0) return [];

  let content = signedDataBytes;
  try {
    const ci = parseCmsContentInfo(signedDataBytes);
    if (ci.contentType === CMS_OIDS.SIGNED_DATA && ci.content) {
      content = ci.content;
    }
  } catch {
    // Direct
  }

  const outer = readTlv(content, 0);
  if (outer.tag !== 0x30) return [];

  let pos = 0;
  const val = outer.value;

  // Skip version, digestAlgorithms, encapContentInfo
  for (let i = 0; i < 3 && pos < val.length; i++) {
    const item = readTlv(val, pos);
    pos += item.totalLen;
  }

  // Skip certificates [0] if present
  if (pos < val.length) {
    const next = readTlv(val, pos);
    if (next.tag === 0xA0) {
      pos += next.totalLen;
    }
  }

  const crls = [];

  // crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
  if (pos < val.length) {
    const next = readTlv(val, pos);
    if (next.tag === 0xA1) { // [1] IMPLICIT SET OF
      let crlPos = 0;
      const crlSet = next.value;
      while (crlPos < crlSet.length) {
        if (crlSet[crlPos] !== 0x30) {
          crlPos++;
          continue;
        }
        const crlTlv = readTlv(crlSet, crlPos);
        crls.push(new Uint8Array(crlSet.subarray(crlPos, crlPos + crlTlv.totalLen)));
        crlPos += crlTlv.totalLen;
      }
    }
  }

  return crls;
}

/**
 * Verify whether a buffer is valid PKCS#7 or CMS SignedData.
 */
export function isCmsSignedData(bytes) {
  if (!bytes || bytes.length < 4) return false;
  try {
    const ci = parseCmsContentInfo(bytes);
    return ci.contentType === CMS_OIDS.SIGNED_DATA;
  } catch {
    return false;
  }
}
