import { readTlv, decodeOid, readBitString } from './der.js';

export const EXTENSION_OIDS = {
  BASIC_CONSTRAINTS: '2.5.29.19',
  KEY_USAGE: '2.5.29.15',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  SUBJECT_KEY_IDENTIFIER: '2.5.29.14',
  AUTHORITY_KEY_IDENTIFIER: '2.5.29.35',
  SUBJECT_ALTERNATIVE_NAME: '2.5.29.17',
  ISSUER_ALTERNATIVE_NAME: '2.5.29.18',
  NAME_CONSTRAINTS: '2.5.29.30',
  CRL_DISTRIBUTION_POINTS: '2.5.29.31',
  CERTIFICATE_POLICIES: '2.5.29.32',
  POLICY_MAPPINGS: '2.5.29.33',
  POLICY_CONSTRAINTS: '2.5.29.36',
  INHIBIT_ANY_POLICY: '2.5.29.54',
  AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1'
};

export const EKU_OIDS = {
  SERVER_AUTH: '1.3.6.1.5.5.7.3.1',
  CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
  CODE_SIGNING: '1.3.6.1.5.5.7.3.3',
  EMAIL_PROTECTION: '1.3.6.1.5.5.7.3.4',
  TIME_STAMPING: '1.3.6.1.5.5.7.3.8',
  OCSP_SIGNING: '1.3.6.1.5.5.7.3.9'
};

export const KEY_USAGE_BITS = {
  DIGITAL_SIGNATURE: 0,
  NON_REPUDIATION: 1,
  KEY_ENCIPHERMENT: 2,
  DATA_ENCIPHERMENT: 3,
  KEY_AGREEMENT: 4,
  KEY_CERT_SIGN: 5,
  CRL_SIGN: 6,
  ENCIPHER_ONLY: 7,
  DECIPHER_ONLY: 8
};

/**
 * Parse an X.509 v3 Extensions sequence.
 * @param {Uint8Array} bytes - Raw DER bytes of the Extensions SEQUENCE
 * @returns {Map<string, Object>} - Map of extension OID to parsed extension object
 */
export function parseExtensions(bytes) {
  const extensions = new Map();
  if (!bytes || bytes.length === 0) return extensions;

  let offset = 0;
  const outer = readTlv(bytes, offset);
  if (outer.tag !== 0x30) return extensions;

  let pos = 0;
  const seqData = outer.value;

  while (pos < seqData.length) {
    const extTlv = readTlv(seqData, pos);
    pos += extTlv.totalLen;

    if (extTlv.tag !== 0x30) continue;

    const parsed = parseExtensionEntry(extTlv.value);
    if (parsed) {
      extensions.set(parsed.oid, parsed);
    }
  }

  return extensions;
}

/**
 * Parse a single Extension entry.
 */
export function parseExtensionEntry(extBytes) {
  let pos = 0;
  const oidTlv = readTlv(extBytes, pos);
  if (oidTlv.tag !== 0x06) return null;
  const oid = decodeOid(oidTlv.value);
  pos += oidTlv.totalLen;

  let critical = false;
  if (pos < extBytes.length) {
    const next = readTlv(extBytes, pos);
    if (next.tag === 0x01) { // BOOLEAN
      critical = next.value.length > 0 && next.value[0] !== 0;
      pos += next.totalLen;
    }
  }

  if (pos >= extBytes.length) return null;
  const valTlv = readTlv(extBytes, pos);
  if (valTlv.tag !== 0x04) return null; // OCTET STRING
  const extValueBytes = valTlv.value;

  const result = {
    oid,
    critical,
    raw: extValueBytes
  };

  try {
    switch (oid) {
      case EXTENSION_OIDS.BASIC_CONSTRAINTS:
        result.parsed = parseBasicConstraints(extValueBytes);
        break;
      case EXTENSION_OIDS.KEY_USAGE:
        result.parsed = parseKeyUsage(extValueBytes);
        break;
      case EXTENSION_OIDS.EXTENDED_KEY_USAGE:
        result.parsed = parseExtendedKeyUsage(extValueBytes);
        break;
      case EXTENSION_OIDS.SUBJECT_KEY_IDENTIFIER:
        result.parsed = parseSubjectKeyIdentifier(extValueBytes);
        break;
      case EXTENSION_OIDS.AUTHORITY_KEY_IDENTIFIER:
        result.parsed = parseAuthorityKeyIdentifier(extValueBytes);
        break;
      case EXTENSION_OIDS.SUBJECT_ALTERNATIVE_NAME:
      case EXTENSION_OIDS.ISSUER_ALTERNATIVE_NAME:
        result.parsed = parseGeneralNames(extValueBytes);
        break;
      case EXTENSION_OIDS.NAME_CONSTRAINTS:
        result.parsed = parseNameConstraints(extValueBytes);
        break;
      case EXTENSION_OIDS.CRL_DISTRIBUTION_POINTS:
        result.parsed = parseCrlDistributionPoints(extValueBytes);
        break;
      case EXTENSION_OIDS.AUTHORITY_INFO_ACCESS:
        result.parsed = parseAuthorityInfoAccess(extValueBytes);
        break;
      default:
        result.parsed = null;
    }
  } catch {
    result.parsed = null;
  }

  return result;
}

/**
 * Parse Basic Constraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
 */
export function parseBasicConstraints(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) {
    return { isCa: false, pathLenConstraint: null };
  }

  let isCa = false;
  let pathLenConstraint = null;
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;

    if (item.tag === 0x01) { // BOOLEAN
      isCa = item.value.length > 0 && item.value[0] !== 0;
    } else if (item.tag === 0x02) { // INTEGER
      let num = 0;
      for (const b of item.value) {
        num = (num << 8) | b;
      }
      pathLenConstraint = num;
    }
  }

  return { isCa, pathLenConstraint };
}

/**
 * Parse Key Usage: BIT STRING
 */
export function parseKeyUsage(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x03) {
    return createEmptyKeyUsage();
  }

  const bitStr = readBitString(outer.value);
  const data = bitStr.data;

  const getBit = (index) => {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = 7 - (index % 8);
    if (byteIndex >= data.length) return false;
    return (data[byteIndex] & (1 << bitIndex)) !== 0;
  };

  return {
    digitalSignature: getBit(KEY_USAGE_BITS.DIGITAL_SIGNATURE),
    nonRepudiation: getBit(KEY_USAGE_BITS.NON_REPUDIATION),
    keyEncipherment: getBit(KEY_USAGE_BITS.KEY_ENCIPHERMENT),
    dataEncipherment: getBit(KEY_USAGE_BITS.DATA_ENCIPHERMENT),
    keyAgreement: getBit(KEY_USAGE_BITS.KEY_AGREEMENT),
    keyCertSign: getBit(KEY_USAGE_BITS.KEY_CERT_SIGN),
    cRLSign: getBit(KEY_USAGE_BITS.CRL_SIGN),
    encipherOnly: getBit(KEY_USAGE_BITS.ENCIPHER_ONLY),
    decipherOnly: getBit(KEY_USAGE_BITS.DECIPHER_ONLY),
    rawBytes: data
  };
}

function createEmptyKeyUsage() {
  return {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    cRLSign: false,
    encipherOnly: false,
    decipherOnly: false,
    rawBytes: new Uint8Array(0)
  };
}

/**
 * Parse Extended Key Usage: SEQUENCE OF KeyPurposeId (OID)
 */
export function parseExtendedKeyUsage(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return { oids: [], serverAuth: false, clientAuth: false, codeSigning: false, emailProtection: false };

  const oids = [];
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;
    if (item.tag === 0x06) {
      oids.push(decodeOid(item.value));
    }
  }

  return {
    oids,
    serverAuth: oids.includes(EKU_OIDS.SERVER_AUTH),
    clientAuth: oids.includes(EKU_OIDS.CLIENT_AUTH),
    codeSigning: oids.includes(EKU_OIDS.CODE_SIGNING),
    emailProtection: oids.includes(EKU_OIDS.EMAIL_PROTECTION),
    timeStamping: oids.includes(EKU_OIDS.TIME_STAMPING),
    ocspSigning: oids.includes(EKU_OIDS.OCSP_SIGNING)
  };
}

/**
 * Parse Subject Key Identifier: OCTET STRING
 */
export function parseSubjectKeyIdentifier(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x04) return { keyIdentifier: bytes };
  return { keyIdentifier: outer.value };
}

/**
 * Parse Authority Key Identifier: SEQUENCE { keyIdentifier [0], authorityCertIssuer [1], authorityCertSerialNumber [2] }
 */
export function parseAuthorityKeyIdentifier(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return { keyIdentifier: null, serialNumber: null };

  let keyIdentifier = null;
  let serialNumber = null;
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;

    if (item.tag === 0x80) { // [0] IMPLICIT KeyIdentifier (OCTET STRING)
      keyIdentifier = item.value;
    } else if (item.tag === 0x82) { // [2] IMPLICIT CertificateSerialNumber (INTEGER)
      serialNumber = Buffer.from(item.value).toString('hex').toUpperCase();
    }
  }

  return { keyIdentifier, serialNumber };
}

/**
 * Parse GeneralNames sequence.
 */
export function parseGeneralNames(bytes) {
  const names = [];
  let offset = 0;
  if (bytes[0] === 0x30) {
    const outer = readTlv(bytes, 0);
    bytes = outer.value;
  }

  let pos = 0;
  while (pos < bytes.length) {
    const item = readTlv(bytes, pos);
    pos += item.totalLen;

    const tagNum = item.tag & 0x1F;
    const strVal = Buffer.from(item.value).toString('utf8');

    switch (tagNum) {
      case 1: // rfc822Name
        names.push({ type: 'email', value: strVal });
        break;
      case 2: // dNSName
        names.push({ type: 'dns', value: strVal });
        break;
      case 6: // uniformResourceIdentifier
        names.push({ type: 'uri', value: strVal });
        break;
      case 7: // iPAddress
        if (item.value.length === 4) {
          names.push({ type: 'ip', value: Array.from(item.value).join('.') });
        } else if (item.value.length === 16) {
          names.push({ type: 'ip', value: Buffer.from(item.value).toString('hex') });
        }
        break;
      default:
        names.push({ type: 'other', tag: tagNum, raw: item.value });
    }
  }

  return names;
}

/**
 * Parse Name Constraints: SEQUENCE { permittedSubtrees [0], excludedSubtrees [1] }
 */
export function parseNameConstraints(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return { permitted: [], excluded: [] };

  const permitted = [];
  const excluded = [];
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;

    if (item.tag === 0xA0) { // [0] permittedSubtrees
      permitted.push(...parseSubtrees(item.value));
    } else if (item.tag === 0xA1) { // [1] excludedSubtrees
      excluded.push(...parseSubtrees(item.value));
    }
  }

  return { permitted, excluded };
}

function parseSubtrees(bytes) {
  const subtrees = [];
  let pos = 0;
  while (pos < bytes.length) {
    const item = readTlv(bytes, pos);
    pos += item.totalLen;
    if (item.tag === 0x30) {
      const gnames = parseGeneralNames(item.value);
      subtrees.push(...gnames);
    }
  }
  return subtrees;
}

/**
 * Parse CRL Distribution Points: SEQUENCE OF DistributionPoint
 */
export function parseCrlDistributionPoints(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return [];

  const points = [];
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;

    if (item.tag === 0x30) {
      const parsed = parseDistributionPoint(item.value);
      if (parsed) points.push(parsed);
    }
  }

  return points;
}

function parseDistributionPoint(bytes) {
  let pos = 0;
  let uri = null;

  while (pos < bytes.length) {
    const item = readTlv(bytes, pos);
    pos += item.totalLen;

    if (item.tag === 0xA0) { // distributionPoint [0]
      const inner = readTlv(item.value, 0);
      if (inner.tag === 0xA0) { // fullName [0]
        const gnames = parseGeneralNames(inner.value);
        const uriName = gnames.find(g => g.type === 'uri');
        if (uriName) uri = uriName.value;
      }
    }
  }

  return uri ? { uri } : null;
}

/**
 * Parse Authority Information Access: SEQUENCE OF AccessDescription
 */
export function parseAuthorityInfoAccess(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return [];

  const access = [];
  let pos = 0;
  const val = outer.value;

  while (pos < val.length) {
    const item = readTlv(val, pos);
    pos += item.totalLen;

    if (item.tag === 0x30) {
      let p = 0;
      const oidTlv = readTlv(item.value, p);
      p += oidTlv.totalLen;

      if (oidTlv.tag === 0x06 && p < item.value.length) {
        const oid = decodeOid(oidTlv.value);
        const locTlv = readTlv(item.value, p);
        const locNames = parseGeneralNames(locTlv.raw);
        access.push({
          method: oid === '1.3.6.1.5.5.7.48.1' ? 'ocsp' : (oid === '1.3.6.1.5.5.7.48.2' ? 'caIssuers' : oid),
          locations: locNames
        });
      }
    }
  }

  return access;
}

/**
 * Validate RFC 5280 name constraints against a candidate host or email.
 */
export function checkHostNameConstraints(constraints, host) {
  if (!constraints || (!constraints.permitted.length && !constraints.excluded.length)) {
    return true;
  }

  const normalizedHost = host.toLowerCase();

  // If excluded subtrees match, fail immediately
  for (const excl of constraints.excluded) {
    if (excl.type === 'dns') {
      const pattern = excl.value.toLowerCase().replace(/^\./, '');
      if (normalizedHost === pattern || normalizedHost.endsWith('.' + pattern)) {
        return false;
      }
    }
  }

  // If permitted subtrees exist, at least one must match
  const dnsPermitted = constraints.permitted.filter(p => p.type === 'dns');
  if (dnsPermitted.length > 0) {
    let matched = false;
    for (const perm of dnsPermitted) {
      const pattern = perm.value.toLowerCase().replace(/^\./, '');
      if (normalizedHost === pattern || normalizedHost.endsWith('.' + pattern)) {
        matched = true;
        break;
      }
    }
    if (!matched) return false;
  }

  return true;
}
