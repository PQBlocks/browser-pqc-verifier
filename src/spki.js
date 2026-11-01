/**
 * SPKI extractor and OID map.
 * Exports:
 *   extractSpki(cert) → { oid: string, publicKeyBytes: Uint8Array }
 *   DEFAULT_OID_MAP   — maps PQC algorithm OIDs → mldsa44/65/87
 *   resolveParams(oid, oidMap) → string | null
 * Pure ASN.1 SPKI unwrapping, no crypto primitives re-implemented
 * (wraps @noble/post-quantum for ML-DSA verify only).
 */
export const DEFAULT_OID_MAP = new Map([
  // [1.3.132.0.35] -> mldsa44 (NIST P-256 equivalent)
  ['1.3.132.0.35', 'mldsa44'],
  // [1.3.132.0.34] -> mldsa65 (NIST P-384 equivalent)
  ['1.3.132.0.34', 'mldsa65'],
  // [1.3.132.0.33] -> mldsa87 (NIST P-521 equivalent)
  ['1.3.132.0.33', 'mldsa87'],
]);

/**
 * Extract SPKI AlgorithmIdentifier OID and raw public key bytes from a parsed certificate.
 * The cert is the output of parseCertificate() — it must contain subjectPublicKeyInfo.
 * Unwraps the AlgorithmIdentifier SEQUENCE, returns the OID string and the raw
 * BIT STRING data (the ML-DSA public key bytes).
 * 
 * @param {import('../src/x509.js').PqCertificate} cert - Parsed certificate from x509.js
 * @returns {{oid: string, publicKeyBytes: Uint8Array}} - OID and raw public key bytes
 * @throws {Error} if cert has no subjectPublicKeyInfo or the SPKI structure is unexpected
 */
export function extractSpki(cert) {
  if (!cert || typeof cert !== 'object') {
    const err = new Error('E29: extractSpki: cert must be a non-null object');
    err.code = 'E29';
    throw err;
  }
  
  const spki = cert.subjectPublicKeyInfo;
  if (!spki || !spki.algorithm || !spki.publicKey) {
    const err = new Error('E29: extractSpki: cert.subjectPublicKeyInfo missing or incomplete');
    err.code = 'E29';
    throw err;
  }
  
  // Decode the algorithm OID from the SPKI AlgorithmIdentifier
  const algOid = spki.algorithm.toString();
  if (!algOid) {
    const err = new Error('E29: extractSpki: SPKI algorithm OID is empty or undefined');
    err.code = 'E29';
    throw err;
  }
  
  // Extract the raw public key bytes (BIT STRING data)
  const pkBytes = spki.publicKey;
  if (!pkBytes || !(pkBytes instanceof Uint8Array)) {
    const err = new Error('E29: extractSpki: SPKI publicKey must be Uint8Array');
    err.code = 'E29';
    throw err;
  }
  
  return {
    oid: algOid,
    publicKeyBytes: pkBytes,
  };
}

/**
 * Resolve an algorithm OID to its ML-DSA parameter name using the override map.
 * Caller-provided oidMap takes precedence over DEFAULT_OID_MAP; DEFAULT_OID_MAP
 * is used as the fallback for keys not present in the override map. Returns the
 * parameter name string (e.g. 'mldsa65') or null if not found.
 * 
 * @param {string} oid - The algorithm OID string (e.g. '1.3.132.0.35')
 * @param {Map<string, string>|undefined} oidMap - Optional override map; if undefined,
 *   only DEFAULT_OID_MAP is used
 * @returns {string|null} - The ML-DSA parameter name, or null if not found
 */
export function resolveParams(oid, oidMap) {
  // Caller-provided oidMap takes precedence (defaults to DEFAULT_OID_MAP per VerifyOptions)
  if (oidMap instanceof Map) {
    const overridden = oidMap.get(oid);
    if (overridden) {
      return overridden;
    }
  }
  
  // Fall back to DEFAULT_OID_MAP
  const defaultParam = DEFAULT_OID_MAP.get(oid);
  if (defaultParam) {
    return defaultParam;
  }
  
  return null;
}

/**
 * Resolve the ML-DSA parameter name from a parsed certificate's SPKI OID,
 * using the default map with optional override.
 * 
 * @param {import('../src/x509.js').PqCertificate} cert - Parsed certificate
 * @param {Map<string, string>|undefined} oidMap - Optional override map
 * @returns {string|null} - The ML-DSA parameter name, or null if not found
 */
export function resolveParamsFromCert(cert, oidMap) {
  const { oid } = extractSpki(cert);
  return resolveParams(oid, oidMap);
}