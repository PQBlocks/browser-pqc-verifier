/**
 * DER TLV reader - pure ASN.1 DER decoding
 * Slice S1: DER TLV reader [P]
 * Exports: readTlv, decodeOid, readBitString, readTime
 * Pure parsing, no X.509 semantics.
 *
 * Errors:
 *   MALFORMED_CERT (E2 truncated, E3 oversized, E6 wrong-length)
 *   UNSUPPORTED_ALGORITHM (unknown tag/length class)
 *   TypeError (E19 type confusion - non-buffer input)
 */

// ASN.1 universal tag numbers
const TAG_SEQUENCE = 0x30;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OBJECT_IDENTIFIER = 0x06;
const TAG_ENUMERATED = 0x0a;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;

// Typed error helpers
function truncatedError(msg) {
  return Object.assign(new Error('MALFORMED_CERT: ' + msg), { code: 'E2' });
}
function oversizedError(msg) {
  return Object.assign(new Error('MALFORMED_CERT: ' + msg), { code: 'E3' });
}
function wrongLengthError(msg) {
  return Object.assign(new Error('MALFORMED_CERT: ' + msg), { code: 'E6' });
}

/**
 * Read a DER TLV element starting at `offset` in `buf`.
 * Returns { tag, value, headerLen, totalLen, nextOffset }
 */
export function readTlv(buf, offset = 0) {
  if (!(buf instanceof Uint8Array) && !Buffer.isBuffer(buf)) {
    throw new TypeError('readTlv: buf must be Uint8Array or Buffer');
  }
  if (typeof offset !== 'number') {
    throw new TypeError('readTlv: offset must be a number');
  }

  const data = buf;

  // Tag byte
  if (offset >= data.length) {
    throw truncatedError('expected tag byte at offset ' + offset);
  }
  const tag = data[offset];
  offset += 1;

  // Length byte(s)
  if (offset >= data.length) {
    throw truncatedError('expected length byte at offset ' + offset);
  }
  const lenByte = data[offset];
  offset += 1;

  let length;
  let headerLen = 2;

  if ((lenByte & 0x80) === 0x00) {
    // Short form: length is the low 7 bits
    length = lenByte & 0x7f;
  } else {
    const numLenBytes = lenByte & 0x7f;
    if (numLenBytes === 0x00 || numLenBytes > 4) {
      throw wrongLengthError('invalid length form byte 0x' + lenByte.toString(16));
    }
    if (offset + numLenBytes > data.length) {
      throw truncatedError('length bytes extend beyond buffer (need ' + numLenBytes + ', have ' + (data.length - offset) + ')');
    }
    length = 0;
    for (let i = 0; i < numLenBytes; i++) {
      length = (length << 8) | data[offset];
      offset += 1;
    }
    headerLen = 2 + numLenBytes;

    // Long-form length must be > 127 (otherwise short form should have been used)
    if (length < 128) {
      throw wrongLengthError('non-minimal length encoding: length ' + length + ' encodable in short form');
    }
  }

  if (offset + length > data.length) {
    throw truncatedError('truncated: value extends beyond buffer (need ' + (offset + length) + ', have ' + data.length + ')');
  }

  const value = data.subarray(offset, offset + length);
  const totalLen = headerLen + length;

  return {
    tag,
    value,
    headerLen,
    length,
    totalLen,
    nextOffset: offset + length,
  };
}

/**
 * Decode a DER Object Identifier (OID) value into dot notation.
 * Input: raw OID content bytes (tag stripped).
 */
export function decodeOid(value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('decodeOid: value must be Uint8Array or Buffer');
  }
  if (value.length === 0) {
    throw wrongLengthError('OID content is empty');
  }

  const bytes = value;
  const components = [];

  // First byte encodes first two arcs: floor(b0 / 40), b0 % 40
  // b0 in [0..79] for first arc in {0,1,2}
  // The standard encoding: first arc * 40 + second arc = b0
  // arc 0: 0-1 (CCITT, ISO)  => b0 0-79
  // arc 2: joint-iso-itu-t  => b0 >= 80
  const b0 = bytes[0];
  if (b0 >= 80) {
    // First arc 2 (joint-iso-itu-t)
    components.push('2');
    let remaining = b0 - 80;
    // rem encodes subsequent arc
    const digits = [];
    do {
      digits.push(remaining % 128);
      remaining = Math.floor(remaining / 128);
    } while (remaining > 0);
    digits.reverse();
    for (const d of digits) {
      components.push(String(d));
    }
    let idx = 1;
    while (idx < bytes.length) {
      components.push(String(decodeBase128(bytes, idx)));
      idx = advanceBase128(bytes, idx);
    }
  } else {
    const arc1 = Math.floor(b0 / 40);
    const arc2 = b0 % 40;
    components.push(String(arc1), String(arc2));
    let idx = 1;
    while (idx < bytes.length) {
      components.push(String(decodeBase128(bytes, idx)));
      idx = advanceBase128(bytes, idx);
    }
  }

  return components.join('.');
}

function decodeBase128(bytes, idx) {
  let value = 0;
  while (true) {
    if (idx >= bytes.length) {
      throw truncatedError('truncated base-128 integer at byte index ' + idx);
    }
    const b = bytes[idx];
    idx += 1;
    // Left-to-right base-128: each subsequent byte shifts the accumulator
    // left by 7 bits, mirroring how DER packs the most-significant byte first.
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0x00) {
      break;
    }
  }
  return value;
}

function advanceBase128(bytes, idx) {
  while (idx < bytes.length) {
    idx += 1;
    if ((bytes[idx - 1] & 0x80) === 0x00) break;
  }
  return idx;
}

/**
 * Read a DER BIT STRING value.
 * Returns { unusedBits: number, data: Uint8Array }
 */
export function readBitString(value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('readBitString: value must be Uint8Array or Buffer');
  }
  if (value.length === 0) {
    throw wrongLengthError('BIT STRING content is empty');
  }
  const unusedBits = value[0];
  if (unusedBits > 7) {
    throw wrongLengthError('invalid unused bits count ' + unusedBits);
  }
  const data = value.subarray(1);
  return { unusedBits, data };
}

/**
 * Read a DER UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ).
 * Returns a Date object.
 */
export function readTime(tag, value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('readTime: value must be Uint8Array or Buffer');
  }

  const text = Buffer.from(value).toString('ascii');

  if (tag === TAG_UTC_TIME) {
    // YYMMDDHHMMSS[Z|+hhmm|-hhmm]
    const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([+-Z].*)?$/.exec(text);
    if (!match) {
      throw wrongLengthError('invalid UTCTime format: ' + text);
    }
    let yy = parseInt(match[1], 10);
    const mo = parseInt(match[2], 10) - 1;
    const dd = parseInt(match[3], 10);
    const hh = parseInt(match[4], 10);
    const mm = parseInt(match[5], 10);
    const ss = parseInt(match[6], 10);
    // 50-99 => 1900+, 00-49 => 2000+
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, mo, dd, hh, mm, ss));
  }

  if (tag === TAG_GENERALIZED_TIME) {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{4})?$/.exec(text);
    if (!match) {
      throw wrongLengthError('invalid GeneralizedTime format: ' + text);
    }
    const year = parseInt(match[1], 10);
    const mo = parseInt(match[2], 10) - 1;
    const dd = parseInt(match[3], 10);
    const hh = parseInt(match[4], 10);
    const mm = parseInt(match[5], 10);
    const ss = parseInt(match[6], 10);
    return new Date(Date.UTC(year, mo, dd, hh, mm, ss));
  }

  throw wrongLengthError('readTime: unexpected tag 0x' + tag.toString(16));
}

/**
 * Decode an ASN.1 INTEGER from DER value bytes.
 */
export function decodeInteger(value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('decodeInteger: value must be Uint8Array or Buffer');
  }
  if (value.length === 0) {
    throw wrongLengthError('INTEGER content is empty');
  }

  // Check for non-minimal negative or positive zero padding
  if (value.length > 1) {
    if (value[0] === 0x00 && (value[1] & 0x80) === 0) {
      throw wrongLengthError('non-minimal INTEGER encoding (redundant leading zero)');
    }
    if (value[0] === 0xFF && (value[1] & 0x80) !== 0) {
      throw wrongLengthError('non-minimal INTEGER encoding (redundant leading 0xFF)');
    }
  }

  let isNegative = (value[0] & 0x80) !== 0;
  let hex = Buffer.from(value).toString('hex');
  let big = BigInt('0x' + (hex || '0'));
  if (isNegative) {
    const bitLen = BigInt(value.length * 8);
    big = big - (1n << bitLen);
  }
  return big;
}

/**
 * Decode an ASN.1 BOOLEAN from DER value bytes.
 */
export function decodeBoolean(value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('decodeBoolean: value must be Uint8Array or Buffer');
  }
  if (value.length !== 1) {
    throw wrongLengthError('BOOLEAN length must be 1, got ' + value.length);
  }
  if (value[0] !== 0x00 && value[0] !== 0xFF) {
    // DER requires 0xFF for TRUE, 0x00 for FALSE
    return value[0] !== 0x00;
  }
  return value[0] === 0xFF;
}

/**
 * Decode ASN.1 string types (UTF8String, PrintableString, IA5String, etc.).
 */
export function decodeString(tag, value) {
  if (!(value instanceof Uint8Array) && !Buffer.isBuffer(value)) {
    throw new TypeError('decodeString: value must be Uint8Array or Buffer');
  }
  const buf = Buffer.from(value);
  switch (tag) {
    case 0x0C: // UTF8String
      return buf.toString('utf8');
    case 0x13: // PrintableString
    case 0x16: // IA5String
    case 0x1A: // VisibleString
      return buf.toString('ascii');
    case 0x1E: // BMPString (UTF-16BE)
      return buf.swap16().toString('utf16le');
    default:
      return buf.toString('utf8');
  }
}

// ---------------------------------------------------------------------------
// DER Encoders (RFC 5280 / ASN.1 DER compliant)
// ---------------------------------------------------------------------------

/**
 * Encode a length in DER format.
 */
export function encodeLength(len) {
  if (typeof len !== 'number' || len < 0) {
    throw new TypeError('encodeLength: len must be non-negative number');
  }
  if (len <= 127) {
    return new Uint8Array([len]);
  }
  const bytes = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xFF);
    temp = temp >> 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

/**
 * Encode a DER TLV element.
 */
export function encodeTlv(tag, valueBytes) {
  if (typeof tag !== 'number') {
    throw new TypeError('encodeTlv: tag must be a number');
  }
  const val = valueBytes instanceof Uint8Array ? valueBytes : new Uint8Array(valueBytes || []);
  const lenHeader = encodeLength(val.length);
  const out = new Uint8Array(1 + lenHeader.length + val.length);
  out[0] = tag;
  out.set(lenHeader, 1);
  out.set(val, 1 + lenHeader.length);
  return out;
}

/**
 * Encode an INTEGER in DER.
 */
export function encodeInteger(val) {
  let big = typeof val === 'bigint' ? val : BigInt(val);
  if (big === 0n) {
    return encodeTlv(0x02, new Uint8Array([0x00]));
  }
  let isNeg = big < 0n;
  if (isNeg) {
    // Two's complement encoding
    let hex = (-big).toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const raw = Buffer.from(hex, 'hex');
    return encodeTlv(0x02, raw);
  }
  let hex = big.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let bytes = Array.from(Buffer.from(hex, 'hex'));
  if (bytes[0] & 0x80) {
    bytes.unshift(0x00);
  }
  return encodeTlv(0x02, new Uint8Array(bytes));
}

/**
 * Encode a BOOLEAN in DER.
 */
export function encodeBoolean(bool) {
  return encodeTlv(0x01, new Uint8Array([bool ? 0xFF : 0x00]));
}

/**
 * Encode an OCTET STRING in DER.
 */
export function encodeOctetString(bytes) {
  return encodeTlv(0x04, bytes);
}

/**
 * Encode a BIT STRING in DER.
 */
export function encodeBitString(data, unusedBits = 0) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data || []);
  const val = new Uint8Array(1 + bytes.length);
  val[0] = unusedBits & 0x07;
  val.set(bytes, 1);
  return encodeTlv(0x03, val);
}

/**
 * Encode an OID in DER.
 */
export function encodeOid(oidStr) {
  if (typeof oidStr !== 'string') {
    throw new TypeError('encodeOid: oidStr must be a string');
  }
  const parts = oidStr.split('.').map(s => parseInt(s, 10));
  if (parts.length < 2) {
    throw new Error('Invalid OID: must have at least 2 components');
  }
  const bytes = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let arc = parts[i];
    const arcBytes = [];
    arcBytes.unshift(arc & 0x7F);
    arc = arc >> 7;
    while (arc > 0) {
      arcBytes.unshift((arc & 0x7F) | 0x80);
      arc = arc >> 7;
    }
    bytes.push(...arcBytes);
  }
  return encodeTlv(0x06, new Uint8Array(bytes));
}

/**
 * Encode a SEQUENCE in DER.
 */
export function encodeSequence(items) {
  const chunks = items.map(it => it instanceof Uint8Array ? it : new Uint8Array(it));
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const val = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    val.set(c, off);
    off += c.length;
  }
  return encodeTlv(0x30, val);
}

/**
 * Encode a SET in DER.
 */
export function encodeSet(items) {
  const chunks = items.map(it => it instanceof Uint8Array ? it : new Uint8Array(it));
  // DER requires SET components to be lexicographically sorted by raw DER bytes
  chunks.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const val = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    val.set(c, off);
    off += c.length;
  }
  return encodeTlv(0x31, val);
}

/**
 * Dump an ASN.1 DER structure into human-readable formatted text.
 */
export function dumpDer(buf, depth = 0) {
  if (!(buf instanceof Uint8Array) && !Buffer.isBuffer(buf)) {
    return '<non-buffer>';
  }
  const lines = [];
  let offset = 0;
  const indent = '  '.repeat(depth);

  while (offset < buf.length) {
    try {
      const tlv = readTlv(buf, offset);
      const isConstructed = (tlv.tag & 0x20) !== 0 || tlv.tag === 0x30 || tlv.tag === 0x31;
      const tagName = getTagName(tlv.tag);

      if (isConstructed) {
        lines.push(`${indent}[${offset.toString(16).padStart(4, '0')}] ${tagName} (len=${tlv.length})`);
        lines.push(dumpDer(tlv.value, depth + 1));
      } else {
        let repr = '';
        if (tlv.tag === 0x06) repr = ' ' + decodeOid(tlv.value);
        else if (tlv.tag === 0x02) repr = ' ' + decodeInteger(tlv.value).toString();
        else if (tlv.tag === 0x01) repr = ' ' + decodeBoolean(tlv.value);
        else if (tlv.tag === 0x17 || tlv.tag === 0x18) repr = ' ' + readTime(tlv.tag, tlv.value).toISOString();
        else repr = ' ' + Buffer.from(tlv.value.subarray(0, 16)).toString('hex') + (tlv.value.length > 16 ? '...' : '');

        lines.push(`${indent}[${offset.toString(16).padStart(4, '0')}] ${tagName} (len=${tlv.length}):${repr}`);
      }
      offset = tlv.nextOffset;
    } catch (e) {
      lines.push(`${indent}[${offset.toString(16).padStart(4, '0')}] <parse-error: ${e.message}>`);
      break;
    }
  }

  return lines.join('\n');
}

function getTagName(tag) {
  switch (tag) {
    case 0x01: return 'BOOLEAN';
    case 0x02: return 'INTEGER';
    case 0x03: return 'BIT STRING';
    case 0x04: return 'OCTET STRING';
    case 0x05: return 'NULL';
    case 0x06: return 'OBJECT IDENTIFIER';
    case 0x0A: return 'ENUMERATED';
    case 0x0C: return 'UTF8String';
    case 0x13: return 'PrintableString';
    case 0x16: return 'IA5String';
    case 0x17: return 'UTCTime';
    case 0x18: return 'GeneralizedTime';
    case 0x30: return 'SEQUENCE';
    case 0x31: return 'SET';
    default:
      if ((tag & 0xC0) === 0x80) return `[${tag & 0x1F}]`;
      if ((tag & 0xC0) === 0xA0) return `[${tag & 0x1F}] (constructed)`;
      return `0x${tag.toString(16).padStart(2, '0')}`;
  }
}
