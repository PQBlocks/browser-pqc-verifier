/**
 * Certificate bundle normalizer - pure parsing, no crypto
 * Slice S0: Certificate bundle normalizer [P]
 */

export function normalizeCertBundle(input) {
  if (input === null || input === undefined) {
    throw new TypeError('normalizeCertBundle: input must be string or Uint8Array, got null/undefined');
  }

  let certs = [];

  if (typeof input === 'string') {
    certs = parsePemString(input);
  } else if (input instanceof Uint8Array || input instanceof Buffer) {
    // Try parsing as PEM string first (PKCS#7 or certificate PEM encoding)
    const str = Buffer.from(input).toString('utf8');
    if (str.includes('-----BEGIN')) {
      certs = parsePemString(str);
    } else if (input.length > 0 && input[0] === 0x30) {
      // DER encoded
      certs = splitDerBundle(input);
      if (certs.length === 0) {
        certs = [input];
      }
    } else {
      certs = [input];
    }
  } else {
    throw new TypeError('normalizeCertBundle: input must be string or Uint8Array, got ' + typeof input);
  }

  if (certs.length === 0) {
    throw new Error('MALFORMED_CERT: no certificates found in input');
  }

  for (const cert of certs) {
    if (!isValidDerCert(cert)) {
      throw new Error('MALFORMED_CERT: certificate is truncated or invalid DER');
    }
  }

  const { leaf, intermediates, anchors } = identifyChainComponents(certs);

  return {
    leaf,
    intermediates,
    anchors
  };
}

function parsePemString(pem) {
  // Check for PEM certificate blocks
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const matches = pem.match(certRegex);

  if (!matches || matches.length === 0) {
    // Might be PKCS#7
    if (pem.includes('-----BEGIN PKCS7-----') || pem.includes('-----BEGIN CMS-----')) {
      return parsePkcs7FromPem(pem);
    }
    throw new Error('MALFORMED_CERT: no certificate blocks found in PEM input');
  }

  return matches.map(block => {
    const b64 = block
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s/g, '');
    const der = Buffer.from(b64, 'base64');
    return new Uint8Array(der);
  });
}

function parsePkcs7FromPem(pem) {
  // Minimal PKCS#7 parser - extract certificates
  // Parse basic PKCS#7/CMS structure
  const pkcs7Regex = /-----BEGIN PKCS7-----[\s\S]*?-----END PKCS7-----/g;
  const matches = pem.match(pkcs7Regex);

  if (!matches) {
    const cmsRegex = /-----BEGIN CMS-----[\s\S]*?-----END CMS-----/g;
    const cmsMatches = pem.match(cmsRegex);
    if (!cmsMatches) {
      throw new Error('MALFORMED_CERT: unrecognized PEM format');
    }
    return parseCmsPem(cmsMatches[0]);
  }

  return parseCmsPem(matches[0]);
}

function parseCmsPem(block) {
  const b64 = block
    .replace(/-----BEGIN PKCS7-----/g, '')
    .replace(/-----END PKCS7-----/g, '')
    .replace(/-----BEGIN CMS-----/g, '')
    .replace(/-----END CMS-----/g, '')
    .replace(/\s/g, '');

  const der = Buffer.from(b64, 'base64');

  // Try to split out embedded certificates
  // Simplified: look for nested BEGIN CERTIFICATE
  const derStr = der.toString('binary');
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

  // For now, treat the whole DER as a bundle if it has 0x30 magic
  if (der.length > 0 && der[0] === 0x30) {
    return splitDerBundle(new Uint8Array(der));
  }

  return [new Uint8Array(der)];
}

function isPkcs7(data) {
  // PKCS#7/CMS outer structure: SEQUENCE with OID 1.2.840.113549.1.7.2 (signedData)
  if (data.length < 4) return false;
  // Check for DER SEQUENCE (0x30) and reasonable length
  if (data[0] !== 0x30) return false;

  // Very simplified check - in real implementation would parse OID
  // Assume PKCS#7 if DER starts with 0x30 0x82 or 0x30 0x81
  return true;
}

function isDerBundle(data) {
  // DER bundle is a sequence of certificates
  // Simplified check: starts with 0x30 (SEQUENCE)
  return data.length > 0 && data[0] === 0x30;
}

function splitDerBundle(data) {
  // Split DER-encoded certificate bundle into individual certs
  // This is simplified - real implementation would parse TLV properly
  const certs = [];
  let offset = 0;

  while (offset < data.length) {
    if (data[offset] !== 0x30) {
      // Not a SEQUENCE, skip byte
      offset++;
      continue;
    }

    // Read length
    const lenByte = data[offset + 1];
    let length;
    let lenBytes = 1;

    if (lenByte & 0x80) {
      const numLenBytes = lenByte & 0x7F;
      if (offset + 2 + numLenBytes > data.length) break;
      length = 0;
      for (let i = 0; i < numLenBytes; i++) {
        length = (length << 8) | data[offset + 2 + i];
      }
      lenBytes = 1 + numLenBytes;
    } else {
      length = lenByte;
    }

    const certLen = 2 + lenBytes + length;
    if (offset + certLen > data.length) break;

    const cert = data.subarray(offset, offset + certLen);
    certs.push(new Uint8Array(cert));

    offset += certLen;
  }

  // If splitting didn't work, return original as single cert
  if (certs.length === 0 || (certs.length === 1 && certs[0].length === data.length)) {
    return [new Uint8Array(data)];
  }

  return certs;
}

function isValidDerCert(cert) {
  // Minimal validation: starts with 0x30 (SEQUENCE) and has reasonable length
  if (!cert || cert.length === 0) return false;
  if (cert[0] !== 0x30) return false;
  if (cert.length < 10) return false;
  if (cert.length > 65536) return false; // E3: oversized

  return true;
}

function identifyChainComponents(certs) {
  // Parse basic subject/issuer info from certificates
  // Simplified: extract subject and issuer from certificate bytes
  // Use a heuristic based on certificate bytes

  // Create fingerprints for each cert
  const fingerprint = (cert) => {
    // Very basic fingerprint - use last 16 bytes hash-ish
    if (cert.length < 16) return String(cert[0]);
    let sum = 0;
    for (let i = cert.length - 16; i < cert.length; i++) {
      sum = (sum + cert[i]) % 256;
    }
    return sum.toString(16);
  };

  // For now, heuristic: smallest cert is leaf, others are intermediates
  const sorted = [...certs].sort((a, b) => a.length - b.length);

  // Identify leaf: first cert (smallest) or cert with unique issuer
  const leaf = sorted[0];
  const intermediates = sorted.filter((_, i) => i > 0);

  // Anchors placeholder - empty for now (would be from trust store)
  const anchors = [];

  return { leaf, intermediates, anchors };
}
