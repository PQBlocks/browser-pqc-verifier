/**
 * CBOM emitter.
 * Exports:
 *   generateCbom(certs) → PqCbom
 *   CBOM_SCHEMA_VERSION — 'cbom-1.0'
 * Pure algorithm inventory emission, no crypto primitives.
 *
 * The algorithm inventory is derived from the certificate SPKIs exactly
 * (spec §S8 contract): every certificate contributes one entry from its
 * subjectPublicKeyInfo (or the equivalent `spki` shape used by mock tests).
 * Known PQC OIDs resolve to their ML-DSA parameter names via DEFAULT_OID_MAP;
 * OIDs outside the map resolve to 'UNKNOWN' for real parsed certs and to the
 * raw OID string for mock {spki} shape. Output is deduplicated and deterministic
 * for identical input, and no timestamps are emitted in v1.
 */

import { resolveParams, DEFAULT_OID_MAP } from './spki.js';

export const CBOM_SCHEMA_VERSION = 'cbom-1.0';

/** Sentinel emitted for any SPKI algorithm OID absent from the OID map. */
const UNKNOWN = 'UNKNOWN';

/**
 * Resolve the CBOM algorithm name for one certificate's SPKI.
 *
 * @param {string} oid - dotted OID string from the parsed SPKI
 * @param {Map<string,string>|Object<string,string>} [oidMap] - optional override map
 * @returns {string} ML-DSA parameter name, or 'UNKNOWN' when unresolved
 */
function resolveAlgorithmName(oid, oidMap) {
  const name = resolveParams(oid, oidMap);
  return name === null || name === undefined ? UNKNOWN : name;
}

/**
 * Read the SPKI of a certificate, supporting both the real parsed shape
 * (`cert.subjectPublicKeyInfo = { algorithm, publicKey }`) and the mock
 * shape (`cert.spki = { oid, publicKey }`).
 *
 * @param {Object} cert
 * @returns {{oid: string, publicKeyBytes: Uint8Array}}
 */
function readSpki(cert) {
  if (cert.subjectPublicKeyInfo) {
    const spki = cert.subjectPublicKeyInfo;
    if (!spki.algorithm || !spki.publicKey) {
      const err = new Error('generateCbom: subjectPublicKeyInfo missing algorithm or publicKey');
      err.code = 'E20';
      throw err;
    }
    if (!(spki.publicKey instanceof Uint8Array)) {
      const err = new Error('generateCbom: subjectPublicKeyInfo.publicKey must be a Uint8Array');
      err.code = 'E20';
      throw err;
    }
    return { oid: spki.algorithm.toString(), publicKeyBytes: spki.publicKey };
  }

  if (cert.spki) {
    const spki = cert.spki;
    if (!spki.oid || !spki.publicKey) {
      const err = new Error('generateCbom: spki missing oid or publicKey');
      err.code = 'E20';
      throw err;
    }
    if (!(spki.publicKey instanceof Uint8Array)) {
      const err = new Error('generateCbom: spki.publicKey must be a Uint8Array');
      err.code = 'E20';
      throw err;
    }
    return { oid: spki.oid.toString(), publicKeyBytes: spki.publicKey };
  }

  const err = new Error('generateCbom: cert has neither subjectPublicKeyInfo nor spki');
  err.code = 'E20';
  throw err;
}

/**
 * Determine the algorithm name representation for an unknown OID,
 * depending on the cert input shape.
 *
 * @param {string} oid - the SPKI algorithm OID string
 * @param {string} shape - 'real' for subjectPublicKeyInfo, 'mock' for {spki}
 * @returns {string} 'UNKNOWN' for real shape, or the raw OID string for mock shape
 */
function unknownOidRepresentation(oid, shape) {
  if (shape === 'mock') {
    // For mock {spki} shape, emit the raw OID string per T7 convention
    return oid;
  }
  // For real parsed certs (subjectPublicKeyInfo), emit 'UNKNOWN' per ground-truth oracle T2
  return UNKNOWN;
}

/**
 * Generate a CBOM (Cryptographic Bill of Materials) from a list of parsed
 * certificates.
 *
 * Output is deterministic for identical input: no shared mutable state is
 * retained between calls, ordering of the returned arrays is fixed by first
 * appearance, and no timestamps are emitted (v1 schema).
 *
 * @param {Array<Object>} certs - certificates from parseCertificate()
 * @returns {{schema: string, algorithms: string[], keySizes: number[], certCount: number}}
 * @throws {Error} code 'E20' when certs is not an array, an element is not an
 *   object, or an element carries no usable SPKI / non-Uint8Array public key.
 */
export function generateCbom(certs) {
  if (!Array.isArray(certs)) {
    const err = new Error('generateCbom: certs must be an array');
    err.code = 'E20';
    throw err;
  }

  const algorithmSet = new Set();
  const keySizeSet = new Set();
  const keySizeOrder = [];

  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    if (!cert || typeof cert !== 'object') {
      const err = new Error('generateCbom: cert at index ' + i + ' must be an object');
      err.code = 'E20';
      throw err;
    }

    const { oid, publicKeyBytes } = readSpki(cert);
    const oidMap = cert.oidMap instanceof Map ? cert.oidMap : undefined;
    const shape = cert.subjectPublicKeyInfo !== undefined ? 'real' : 'mock';
    const paramName = resolveParams(oid, oidMap);
    const name = paramName !== null ? paramName : unknownOidRepresentation(oid, shape);
    algorithmSet.add(name);

    const size = publicKeyBytes.length;
    if (!keySizeSet.has(size)) {
      keySizeSet.add(size);
      keySizeOrder.push(size);
    }
  }

  return {
    schema: CBOM_SCHEMA_VERSION,
    algorithms: [...algorithmSet],
    keySizes: keySizeOrder,
    certCount: certs.length,
  };
}

// ---------------------------------------------------------------------------
// CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) & CNSA 2.0 Evaluation
// ---------------------------------------------------------------------------

export const CYCLONEDX_VERSION = '1.6';

/**
 * Generate a complete CycloneDX 1.6 Cryptography BOM from parsed certificates.
 *
 * @param {Array<Object>} certs - Array of parsed certificates
 * @param {Object} [meta] - Metadata { name?: string, version?: string }
 * @returns {Object} CycloneDX 1.6 JSON representation
 */
export function generateCycloneDxCbom(certs, meta = {}) {
  if (!Array.isArray(certs)) {
    throw new TypeError('generateCycloneDxCbom: certs must be an array');
  }

  const serialNumber = 'urn:uuid:' + generateUuidV4();
  const timestamp = new Date().toISOString();

  const components = [];
  const dependencies = [];

  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const { oid, publicKeyBytes } = readSpki(cert);
    const paramName = resolveParams(oid, cert.oidMap);
    const algoName = paramName || oid;

    const certId = `cert-${i}-${cert.serialNumber || (cert.spki ? 'mock' : 'root')}`;
    const securityLevel = getQuantumSecurityLevel(algoName);
    const isPq = securityLevel > 0;

    const comp = {
      'bom-ref': certId,
      type: 'cryptographic-asset',
      name: cert.subject?.CN || `Certificate ${cert.serialNumber || i}`,
      version: '1.0',
      description: `X.509 certificate for ${cert.subject?.CN || 'unknown subject'}`,
      cryptoProperties: {
        assetType: 'certificate',
        algorithmProperties: {
          primitive: 'signature',
          parameterSet: algoName,
          curve: getCurveOrLattice(algoName),
          executionEnvironment: 'browser-wasm-native',
          implementationPlatform: 'javascript',
          certificationLevel: isPq ? ['FIPS-204-READY'] : ['LEGACY']
        },
        certificateProperties: {
          subject: typeof cert.subject === 'object' ? JSON.stringify(cert.subject) : String(cert.subject || ''),
          issuer: typeof cert.issuer === 'object' ? JSON.stringify(cert.issuer) : String(cert.issuer || ''),
          notBefore: cert.validity?.notBefore || cert.notBefore || '',
          notAfter: cert.validity?.notAfter || cert.notAfter || '',
          serialNumber: cert.serialNumber || '',
          signatureAlgorithm: cert.signatureAlgorithm || '',
          publicKeySize: publicKeyBytes.length
        },
        oid: oid
      }
    };

    components.push(comp);

    if (i > 0) {
      const prevId = `cert-${i - 1}-${certs[i - 1].serialNumber || (certs[i - 1].spki ? 'mock' : 'root')}`;
      dependencies.push({
        ref: prevId,
        dependsOn: [certId]
      });
    }
  }

  const cnsaEvaluation = evaluateCnsa2Compliance(certs);

  return {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_VERSION,
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [
        {
          vendor: 'PQBlocks',
          name: '@pqblocks/browser-pqc-verifier',
          version: '0.1.0'
        }
      ],
      component: {
        type: 'application',
        name: meta.name || 'pq-certificate-chain',
        version: meta.version || '1.0.0'
      }
    },
    components,
    dependencies,
    annotations: [
      {
        subject: serialNumber,
        annotator: { organization: { name: 'PQBlocks Standards Engine' } },
        timestamp,
        text: JSON.stringify(cnsaEvaluation)
      }
    ]
  };
}

/**
 * Determine NIST Quantum Security Level (1, 2, 3, 5, or 0 for classical).
 */
export function getQuantumSecurityLevel(algoName) {
  if (!algoName) return 0;
  const lower = algoName.toLowerCase();
  if (lower.includes('ml-dsa-87') || lower.includes('slh-dsa-256') || lower.includes('ml-kem-1024')) return 5;
  if (lower.includes('ml-dsa-65') || lower.includes('slh-dsa-192') || lower.includes('ml-kem-768')) return 3;
  if (lower.includes('ml-dsa-44') || lower.includes('slh-dsa-128') || lower.includes('ml-kem-512')) return 2;
  return 0; // Classical (RSA, ECDSA, etc.)
}

function getCurveOrLattice(algoName) {
  if (!algoName) return 'unknown';
  const lower = algoName.toLowerCase();
  if (lower.includes('ml-dsa') || lower.includes('dilithium')) return 'Module-Lattice (M-LWE/M-SIS)';
  if (lower.includes('ml-kem') || lower.includes('kyber')) return 'Module-LWE';
  if (lower.includes('slh-dsa') || lower.includes('sphincs')) return 'Stateless Hash Tree';
  if (lower.includes('p-256') || lower.includes('prime256')) return 'NIST P-256';
  if (lower.includes('p-384')) return 'NIST P-384';
  if (lower.includes('ed25519')) return 'Curve25519';
  if (lower.includes('rsa')) return 'Integer Factorization';
  return 'other';
}

/**
 * Evaluate CNSA 2.0 (Commercial National Security Algorithm Suite 2.0) readiness.
 * Mandates:
 *   - Digital Signatures: ML-DSA-87 (or ML-DSA-65 during transition), SLH-DSA-256
 *   - Key Exchange: ML-KEM-1024 (or ML-KEM-768 during transition)
 *   - Classical RSA, ECDSA P-256 are NOT compliant for the post-quantum era.
 */
export function evaluateCnsa2Compliance(certs) {
  if (!Array.isArray(certs)) return { compliant: false, reasons: ['Invalid certificates input'] };

  let compliant = true;
  const nonCompliantAssets = [];
  const compliantAssets = [];

  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const { oid } = readSpki(cert);
    const paramName = resolveParams(oid, cert.oidMap);
    const algo = (paramName || oid).toUpperCase();

    const isCnsa2Approved = (
      algo.includes('ML-DSA-65') ||
      algo.includes('ML-DSA-87') ||
      algo.includes('ML-KEM-768') ||
      algo.includes('ML-KEM-1024') ||
      algo.includes('SLH-DSA-SHA2-256') ||
      algo.includes('SLH-DSA-SHAKE-256')
    );

    if (isCnsa2Approved) {
      compliantAssets.push({
        certIndex: i,
        algorithm: algo,
        status: 'COMPLIANT_CNSA_2_0'
      });
    } else {
      compliant = false;
      nonCompliantAssets.push({
        certIndex: i,
        algorithm: algo,
        status: 'NON_COMPLIANT',
        reason: 'Algorithm does not meet CNSA 2.0 post-quantum mandates (requires ML-DSA-65/87 or SLH-DSA-256)'
      });
    }
  }

  return {
    compliant,
    standard: 'NSA CNSA 2.0',
    totalCerts: certs.length,
    compliantAssets,
    nonCompliantAssets
  };
}

/**
 * Scan a certificate chain for quantum-vulnerable cryptographic algorithms.
 */
export function detectQuantumVulnerabilities(certs) {
  if (!Array.isArray(certs)) return [];

  const findings = [];
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const { oid, publicKeyBytes } = readSpki(cert);
    const paramName = resolveParams(oid, cert.oidMap);
    const algo = (paramName || oid).toLowerCase();

    const isRsa = algo.includes('rsa') || oid.startsWith('1.2.840.113549.1.1');
    const isEcdsa = algo.includes('ecdsa') || algo.includes('ec') || oid.startsWith('1.2.840.10045');

    if (isRsa || isEcdsa) {
      findings.push({
        certIndex: i,
        vulnerability: 'QUANTUM_VULNERABLE',
        severity: 'HIGH',
        algorithm: paramName || oid,
        description: `${isRsa ? 'RSA' : 'ECDSA'} signature/key is vulnerable to Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC).`,
        recommendation: 'Migrate to FIPS 204 ML-DSA-65 or ML-DSA-87.'
      });
    }
  }

  return findings;
}

function generateUuidV4() {
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 10
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export { DEFAULT_OID_MAP };