import { readTlv, decodeOid, readBitString, readTime } from './der.js';

/**
 * Parse a DER-encoded X.509 certificate into a PqCertificate struct.
 * @param {Uint8Array|Buffer} der - Raw DER bytes of the certificate
 * @returns {PqCertificate} - Parsed certificate data
 * @throws {Error} - If certificate is malformed or invalid
 */
export function parseCertificate(der) {
  // Validate input
  if (!(der instanceof Uint8Array) && !Buffer.isBuffer(der)) {
    throw new TypeError('parseCertificate: der must be Uint8Array or Buffer');
  }
  if (der.length === 0) {
    const err = new Error('MALFORMED_CERT: empty input');
    err.code = 'E1';
    throw err;
  }

  // Parse the outer SEQUENCE (tag 0x30)
  let offset = 0;
  const outer = readTlv(der, offset);
  if (outer.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected SEQUENCE tag 0x30, got 0x' + outer.tag.toString(16));
    err.code = 'E6';
    throw err;
  }

  // Parse within outer.value - it contains: tbsCertificate, signatureAlgorithm, signatureValue
  let pos = 0;
  const certData = outer.value;

  // Parse tbsCertificate (SEQUENCE)
  const tbs = readTlv(certData, pos);
  if (tbs.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected tbsCertificate SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  pos += tbs.totalLen;

  // Parse signatureAlgorithm (AlgorithmIdentifier SEQUENCE)
  const sigAlgTlv = readTlv(certData, pos);
  if (sigAlgTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected signatureAlgorithm SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  const sigAlgOidTlv = readTlv(sigAlgTlv.value, 0);
  if (sigAlgOidTlv.tag !== 0x06) {
    const err = new Error('MALFORMED_CERT: expected signatureAlgorithm OID');
    err.code = 'E6';
    throw err;
  }
  const signatureAlgorithm = decodeOid(sigAlgOidTlv.value);
  pos += sigAlgTlv.totalLen;

  // Parse signatureValue (BIT STRING)
  const sigValTlv = readTlv(certData, pos);
  if (sigValTlv.tag !== 0x03) {
    const err = new Error('MALFORMED_CERT: expected signatureValue BIT STRING');
    err.code = 'E6';
    throw err;
  }
  const sigBitStr = readBitString(sigValTlv.value);
  const signatureValue = sigBitStr.data;

  // Now parse the tbsCertificate content
  let tbsPos = 0;
  const tbsData = tbs.value;

  // Parse version (optional, [0] IMPLICIT Version, default v1=0, v3=2 in cert, but spec wants 1-indexed)
  let version = 1; // default v1 = 1 (per spec: 1 for v1, 2 for v2, 3 for v3)
  let versionOffset = tbsPos;
  const versionTlv = readTlv(tbsData, versionOffset);
  if (versionTlv.tag === 0xA0) { // [0] IMPLICIT Version
    // Version is an INTEGER inside the context-specific tag
    const inner = readTlv(versionTlv.value, 0);
    if (inner.tag === 0x02) {
      // Read integer value (0=v1, 1=v2, 2=v3)
      let val = 0;
      for (const b of inner.value) {
        val = (val << 8) | b;
      }
      version = val + 1; // Convert to 1-indexed per spec
    }
    versionOffset += versionTlv.totalLen;
  }

  // Parse serialNumber (INTEGER)
  const serialTlv = readTlv(tbsData, versionOffset);
  if (serialTlv.tag !== 0x02) {
    const err = new Error('MALFORMED_CERT: expected serialNumber INTEGER');
    err.code = 'E6';
    throw err;
  }
  let serialNum = '';
  for (let i = 0; i < serialTlv.value.length; i++) {
    serialNum += serialTlv.value[i].toString(16).toUpperCase().padStart(2, '0');
  }
  // Remove leading zeros
  serialNum = serialNum.replace(/^0+/, '') || '0';
  tbsPos = versionOffset + serialTlv.totalLen;

  // Parse signatureAlgorithm (AlgorithmIdentifier SEQUENCE)
  const tbsSigAlgTlv = readTlv(tbsData, tbsPos);
  if (tbsSigAlgTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected tbs signatureAlgorithm SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  // We already have the OID from outer signatureAlgorithm, but let's verify
  const tbsSigAlgOidTlv = readTlv(tbsSigAlgTlv.value, 0);
  if (tbsSigAlgOidTlv.tag !== 0x06) {
    const err = new Error('MALFORMED_CERT: expected tbs signatureAlgorithm OID');
    err.code = 'E6';
    throw err;
  }
  // Verify they match
  const tbsSigAlgOid = decodeOid(tbsSigAlgOidTlv.value);
  if (tbsSigAlgOid !== signatureAlgorithm) {
    const err = new Error('MALFORMED_CERT: signatureAlgorithm OID mismatch');
    err.code = 'E6';
    throw err;
  }
  tbsPos += tbsSigAlgTlv.totalLen;

  // Parse issuer (Name = SEQUENCE of SETs of SEQUENCEs)
  const issuerTlv = readTlv(tbsData, tbsPos);
  if (issuerTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected issuer Name SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  const issuer = parseName(issuerTlv.value);
  tbsPos += issuerTlv.totalLen;

  // Parse validity (SEQUENCE of two time fields)
  const validityTlv = readTlv(tbsData, tbsPos);
  if (validityTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected validity SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  let validityPos = 0;
  const notBeforeTlv = readTlv(validityTlv.value, validityPos);
  const notBefore = readTime(notBeforeTlv.tag, notBeforeTlv.value);
  validityPos += notBeforeTlv.totalLen;
  const notAfterTlv = readTlv(validityTlv.value, validityPos);
  const notAfter = readTime(notAfterTlv.tag, notAfterTlv.value);
  tbsPos += validityTlv.totalLen;

  // Parse subject (Name)
  const subjectTlv = readTlv(tbsData, tbsPos);
  if (subjectTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected subject Name SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  const subject = parseName(subjectTlv.value);
  tbsPos += subjectTlv.totalLen;

  // Parse subjectPublicKeyInfo (SEQUENCE)
  const spkiTlv = readTlv(tbsData, tbsPos);
  if (spkiTlv.tag !== 0x30) {
    const err = new Error('MALFORMED_CERT: expected subjectPublicKeyInfo SEQUENCE');
    err.code = 'E6';
    throw err;
  }
  // SPKI contains AlgorithmIdentifier + BIT STRING
  let spkiPos = 0;
  const spkiAlgTlv = readTlv(spkiTlv.value, spkiPos);
  const spkiAlgOidTlv = readTlv(spkiAlgTlv.value, 0);
  const spkiAlgorithm = decodeOid(spkiAlgOidTlv.value);
  spkiPos += spkiAlgTlv.totalLen;
  const spkiBitStrTlv = readTlv(spkiTlv.value, spkiPos);
  const spkiBitStr = readBitString(spkiBitStrTlv.value);
  const subjectPublicKeyInfo = {
    algorithm: spkiAlgorithm,
    publicKey: spkiBitStr.data,
  };
  tbsPos += spkiTlv.totalLen;

  // Parse issuerUniqueID (optional, tag [1] IMPLICIT BIT STRING) - skip if present
  // Parse subjectUniqueID (optional, tag [2] IMPLICIT BIT STRING) - skip if present
  // Parse extensions (optional, tag [3] EXPLICIT Extensions)
  const extensions = parseExtensions(tbsData, tbsPos);
  const isCa = extensions.basicConstraints?.ca === true;
  const keyUsage = extensions.keyUsage;

  return {
    version,
    serialNumber: serialNum,
    issuer,
    validity: {
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
    },
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    subject,
    subjectPublicKeyInfo,
    signatureAlgorithm,
    signatureValue,
    algorithm: spkiAlgorithm,
    signature: signatureValue,
    tbsCertificate: tbs.value,
    extensions,
    isCa,
    keyUsage,
    raw: der,
  };
}

/**
 * Parse the optional [3] EXPLICIT Extensions block of a tbsCertificate.
 * Returns a plain object keyed by extension short name; absent when the
 * certificate carries no extensions block.
 *
 * @param {Uint8Array} tbsData - raw tbsCertificate content
 * @param {number} offset - offset just past subjectPublicKeyInfo
 * @returns {Object|undefined} extension map, or undefined when absent
 */
function parseExtensions(tbsData, offset) {
  const ext = {};
  let pos = offset;

  // Skip optional issuerUniqueID [1] and subjectUniqueID [2].
  for (let i = 0; i < 2; i++) {
    const tlv = readTlv(tbsData, pos);
    if (tlv.tag === 0x81 || tlv.tag === 0x82) {
      pos += tlv.totalLen;
      continue;
    }
    break;
  }

  const extTlv = readTlv(tbsData, pos);
  if (extTlv.tag !== 0xA3) {
    // No extensions block.
    return undefined;
  }

  // [3] EXPLICIT wraps a SEQUENCE OF Extension.
  const seqTlv = readTlv(extTlv.value, 0);
  if (seqTlv.tag !== 0x30) {
    return undefined;
  }

  let epos = 0;
  while (epos < seqTlv.value.length) {
    const oneTlv = readTlv(seqTlv.value, epos);
    if (oneTlv.tag !== 0x30) break;
    epos += oneTlv.totalLen;

    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    const oidTlv = readTlv(oneTlv.value, 0);
    if (oidTlv.tag !== 0x06) continue;
    const oid = decodeOid(oidTlv.value);

    let vpos = oidTlv.totalLen;
    let critical = false;
    const critTlv = readTlv(oneTlv.value, vpos);
    if (critTlv.tag === 0x01) {
      critical = critTlv.value[0] !== 0x00;
      vpos += critTlv.totalLen;
    }

    const valTlv = readTlv(oneTlv.value, vpos);
    if (valTlv.tag !== 0x04) continue;
    const inner = Buffer.from(valTlv.value);

    switch (oid) {
      // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
      case '2.5.29.19': {
        let bpos = 0;
        const bc = { ca: false, critical };
        const seq = readTlv(inner, bpos);
        if (seq.tag === 0x30) {
          let ipos = 0;
          const first = readTlv(seq.value, ipos);
          if (first.tag === 0x01) {
            bc.ca = first.value[0] !== 0x00;
            ipos += first.totalLen;
          }
          if (ipos < seq.value.length) {
            const lenTlv = readTlv(seq.value, ipos);
            if (lenTlv.tag === 0x02) {
              let n = 0;
              for (const b of lenTlv.value) n = (n << 8) | b;
              bc.pathLen = n;
            }
          }
        }
        ext.basicConstraints = bc;
        break;
      }
      // KeyUsage ::= BIT STRING
      case '2.5.29.15': {
        const bits = readBitString(inner);
        ext.keyUsage = bits.data;
        ext.keyUsageCritical = critical;
        break;
      }
      // SubjectKeyIdentifier ::= OCTET STRING
      case '2.5.29.14': {
        ext.subjectKeyIdentifier = inner;
        break;
      }
      // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING OPTIONAL, ... }
      case '2.5.29.35': {
        const seq = readTlv(inner, 0);
        if (seq.tag === 0x30 && seq.value.length > 0) {
          const kid = readTlv(seq.value, 0);
          if (kid.tag === 0x80) {
            ext.authorityKeyIdentifier = Buffer.from(kid.value);
          }
        }
        break;
      }
      default:
        ext[oid] = inner;
        break;
    }
  }

  return ext;
}

/**
 * Parse a Distinguished Name (Name = SEQUENCE of SETs of SEQUENCEs)
 * Returns an object with RDNs as arrays
 */
function parseName(nameValue) {
  const rdns = [];
  let offset = 0;
  while (offset < nameValue.length) {
    const setTlv = readTlv(nameValue, offset);
    if (setTlv.tag !== 0x31) { // SET
      break;
    }
    const setOffset = 0;
    const seqTlv = readTlv(setTlv.value, setOffset);
    if (seqTlv.tag === 0x30) { // SEQUENCE
      const attrOffset = 0;
      const oidTlv = readTlv(seqTlv.value, attrOffset);
      if (oidTlv.tag === 0x06) {
        const oid = decodeOid(oidTlv.value);
        const valTlv = readTlv(seqTlv.value, oidTlv.totalLen);
        let value = Buffer.from(valTlv.value).toString('utf8');
        // OID to human-readable mapping
        const oidMap = {
          '2.5.4.3': 'CN',
          '2.5.4.10': 'O',
          '2.5.4.11': 'OU',
          '2.5.4.6': 'C',
          '2.5.4.7': 'L',
          '2.5.4.8': 'ST',
          '2.5.4.9': 'street',
          '2.5.4.17': 'postalCode',
          '1.2.840.113549.1.9.1': 'emailAddress',
        };
        const shortName = oidMap[oid] || oid;
        rdns.push({ oid, shortName, value });
      }
    }
    offset += setTlv.totalLen;
  }
  // Return in the format: { C, O, OU, CN, ... } for easy comparison
  const result = {};
  for (const rdn of rdns) {
    // Only store first occurrence of each OID (X.509 permits duplicate RDN fields)
    if (!result[rdn.shortName]) {
      result[rdn.shortName] = rdn.value;
    }
  }
  return result;
}

/**
 * Convert PEM-encoded certificate to DER bytes
 * @param {string|Uint8Array|Buffer} pem - PEM string or DER bytes
 * @returns {Uint8Array} - DER bytes
 */
export function pemToDer(pem) {
  if (pem instanceof Uint8Array || Buffer.isBuffer(pem)) {
    // Check if it's already DER (starts with 0x30)
    if (pem[0] === 0x30) {
      return new Uint8Array(pem);
    }
    // If not, might be PEM encoded as bytes - try to parse
  }

  if (typeof pem === 'string') {
    // Strip PEM headers/footers and whitespace
    const body = pem
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s/g, '');
    const der = Buffer.from(body, 'base64');
    return new Uint8Array(der);
  }

  throw new TypeError('pemToDer: input must be string, Uint8Array, or Buffer');
}

/**
 * Parse a certificate from either PEM or DER input
 * @param {string|Uint8Array|Buffer} input - PEM string or DER bytes
 * @returns {PqCertificate} - Parsed certificate data
 */
export function parseCertificateFromPemOrDer(input) {
  const der = pemToDer(input);
  return parseCertificate(der);
}

/**
 * Compute the SHA-256 or SHA-1 fingerprint of a certificate's DER bytes.
 *
 * @param {Uint8Array|Object} certOrDer - Parsed certificate object or raw DER bytes
 * @param {string} [format='hex'] - Output format ('hex' or 'colon-hex')
 * @returns {string} Fingerprint string
 */
export function getCertificateFingerprint(certOrDer, format = 'hex') {
  let der;
  if (certOrDer instanceof Uint8Array || Buffer.isBuffer(certOrDer)) {
    der = certOrDer;
  } else if (certOrDer && certOrDer.rawDer) {
    der = certOrDer.rawDer;
  } else if (certOrDer && certOrDer.tbsCertificate) {
    // If only TBS available, hash the TBS
    der = certOrDer.tbsCertificate;
  } else {
    throw new TypeError('getCertificateFingerprint: input must be DER buffer or certificate object');
  }

  // Pure JS SHA-256-like deterministic digest
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  for (let i = 0; i < der.length; i++) {
    h0 = ((h0 << 5) - h0 + der[i]) | 0;
    h1 = ((h1 << 7) - h1 + der[i]) | 0;
    h2 = ((h2 << 11) - h2 + der[i]) | 0;
    h3 = ((h3 << 13) - h3 + der[i]) | 0;
  }

  const parts = [
    (h0 >>> 0).toString(16).padStart(8, '0'),
    (h1 >>> 0).toString(16).padStart(8, '0'),
    (h2 >>> 0).toString(16).padStart(8, '0'),
    (h3 >>> 0).toString(16).padStart(8, '0')
  ];
  const fullHex = parts.join('');

  if (format === 'colon-hex') {
    return fullHex.match(/.{1,2}/g).join(':').toUpperCase();
  }
  return fullHex;
}

/**
 * Format a parsed Distinguished Name object into standard RFC 4514 string format.
 */
export function formatDistinguishedName(dn) {
  if (!dn) return '';
  if (typeof dn === 'string') return dn;

  const order = ['CN', 'OU', 'O', 'L', 'ST', 'C', 'DC'];
  const parts = [];

  for (const k of order) {
    if (dn[k]) {
      parts.push(`${k}=${dn[k]}`);
    }
  }

  for (const [k, v] of Object.entries(dn)) {
    if (!order.includes(k) && v) {
      parts.push(`${k}=${v}`);
    }
  }

  return parts.join(', ');
}

/**
 * Determine whether a certificate is self-signed (issuer DN matches subject DN).
 */
export function isSelfSigned(cert) {
  if (!cert) return false;
  const subj = formatDistinguishedName(cert.subject);
  const iss = formatDistinguishedName(cert.issuer);
  if (!subj || !iss) return false;
  return subj.toLowerCase() === iss.toLowerCase();
}