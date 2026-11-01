/**
 * RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures (PEM parser & encoder)
 * Pure format encoder/decoder, no crypto primitives.
 */

export const PEM_TYPES = {
  CERTIFICATE: 'CERTIFICATE',
  CRL: 'X509 CRL',
  CERT_REQ: 'CERTIFICATE REQUEST',
  PKCS7: 'PKCS7',
  CMS: 'CMS',
  PUBLIC_KEY: 'PUBLIC KEY',
  PRIVATE_KEY: 'PRIVATE KEY'
};

const PEM_BLOCK_REGEX = /-----BEGIN ([A-Z0-9 -]+)-----([A-Za-z0-9+/=\s]+?)-----END \1-----/g;

/**
 * Parse an RFC 7468 PEM text string into an array of parsed PEM objects.
 *
 * @param {string} text - PEM text input
 * @returns {Array<{type: string, headers: Object, bytes: Uint8Array}>}
 * @throws {TypeError} if text is not a string
 */
export function parsePem(text) {
  if (typeof text !== 'string') {
    throw new TypeError('parsePem: text must be a string');
  }

  const results = [];
  let match;
  PEM_BLOCK_REGEX.lastIndex = 0;

  while ((match = PEM_BLOCK_REGEX.exec(text)) !== null) {
    const type = match[1].trim();
    const bodyWithHeaders = match[2];

    const lines = bodyWithHeaders.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const headers = {};
    const base64Lines = [];

    let inHeaders = true;
    for (const line of lines) {
      if (inHeaders && line.includes(':')) {
        const colonIdx = line.indexOf(':');
        const hKey = line.substring(0, colonIdx).trim();
        const hVal = line.substring(colonIdx + 1).trim();
        headers[hKey] = hVal;
      } else {
        inHeaders = false;
        base64Lines.push(line);
      }
    }

    const b64Str = base64Lines.join('').replace(/\s/g, '');
    let bytes;
    try {
      bytes = new Uint8Array(Buffer.from(b64Str, 'base64'));
    } catch {
      continue;
    }

    if (bytes.length > 0) {
      results.push({
        type,
        headers,
        bytes
      });
    }
  }

  return results;
}

/**
 * Encode raw DER bytes into an RFC 7468 PEM block.
 *
 * @param {Uint8Array} bytes - Raw DER bytes
 * @param {string} type - PEM type label (e.g. 'CERTIFICATE')
 * @param {Object} [headers] - Optional headers map
 * @returns {string} Formatted PEM block
 */
export function encodePem(bytes, type = PEM_TYPES.CERTIFICATE, headers = {}) {
  if (!(bytes instanceof Uint8Array) && !Buffer.isBuffer(bytes)) {
    throw new TypeError('encodePem: bytes must be Uint8Array or Buffer');
  }

  const b64 = Buffer.from(bytes).toString('base64');
  const chunks = b64.match(/.{1,64}/g) || [];

  const headerLines = [];
  for (const [k, v] of Object.entries(headers)) {
    headerLines.push(`${k}: ${v}`);
  }

  const parts = [`-----BEGIN ${type}-----`];
  if (headerLines.length > 0) {
    parts.push(...headerLines);
    parts.push(''); // blank line between headers and body
  }
  parts.push(...chunks);
  parts.push(`-----END ${type}-----`);

  return parts.join('\n') + '\n';
}

/**
 * Find all PEM blocks matching a specific type.
 */
export function findPemBlocks(text, type) {
  const all = parsePem(text);
  if (!type) return all;
  const target = type.toUpperCase();
  return all.filter(p => p.type.toUpperCase() === target);
}

/**
 * Check if a string contains valid PEM armor markers.
 */
export function isPem(text) {
  if (typeof text !== 'string') return false;
  return text.includes('-----BEGIN ') && text.includes('-----END ');
}
