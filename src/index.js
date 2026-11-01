/**
 * Post-Quantum Certificate and Chain Verifier — Public API entry point.
 *
 * Composes certificate parsing, post-quantum signature verification,
 * revocation checking, and CBOM generation into a unified package.
 *
 * @module @pqblocks/browser-pqc-verifier
 */

/** Deepest chain depth allowed if no maxDepth option given */
export const DEFAULT_MAX_DEPTH = 5;

/** Pre-mapped OIDs for the most common PQ algorithm identifiers */
export const DEFAULT_OID_MAP = new Map([
  ['1.3.132.0.35', 'mldsa44'],
  ['1.3.132.0.34', 'mldsa65'],
  ['1.3.132.0.33', 'mldsa87'],
]);

// ---- re-export the composed modules so consumers get one namespace ------
export { CBOM_SCHEMA_VERSION } from './cbom.js';
export { verifyChain } from './chain.js';
export { generateCbom } from './cbom.js';
export { parseCertificate, pemToDer, parseCertificateFromPemOrDer, getCertificateFingerprint, formatDistinguishedName, isSelfSigned } from './x509.js';
export { extractSpki, resolveParams, resolveParamsFromCert } from './spki.js';
export { verify as verifyMlDsa, ML_DSA_PARAMS } from './mldsa.js';
export {
  MldsaVerificationError,
  e9Error,
  e23Error,
} from './mldsa.js';
export { readTlv, decodeOid, readBitString, readTime } from './der.js';
export { loadTrustAnchorsFromPem, loadTrustAnchorsFromDer, TrustStore } from './trust-anchors.js';
export { verifySlhDsa, SLH_DSA_PARAMS, SLH_DSA_OIDS, SlhdsaVerificationError } from './slhdsa.js';
export { parseExtensions, EXTENSION_OIDS, EKU_OIDS, checkHostNameConstraints } from './extensions.js';
export { generateCycloneDxCbom, evaluateCnsa2Compliance, detectQuantumVulnerabilities } from './cbom.js';
export { evaluateChainPolicy, PQC_POLICY_PROFILES, CryptoPolicyError, isPurePqChain, calculateMigrationReadiness } from './policy.js';
export { parseOcspResponse, OCSP_RESPONSE_STATUS, OcspError } from './ocsp.js';
export { parseCmsContentInfo, extractCmsCertificates, extractCmsCrls } from './cms.js';
export { parsePem, encodePem, findPemBlocks, isPem, PEM_TYPES } from './pem.js';

// Local imports for implementation functions
import { parseCertificate } from './x509.js';
import { parseCertificateFromPemOrDer } from './x509.js';
import { generateCbom } from './cbom.js';
import { verifyChain } from './chain.js';
import { readTlv } from './der.js';
import { loadTrustAnchorsFromPem as loadTrustAnchorsFromPemTtl, loadTrustAnchorsFromDer as loadTrustAnchorsFromDerTtl } from './trust-anchors.js';

// Matches one PEM CERTIFICATE block (BEGIN + body + END) non-greedily.
// Declared with the /g flag so String.match() returns every block separately.
const PEM_CERT_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/**
 * Parse one certificate input: DER bytes go straight to the DER parser
 * (so E1 empty / E2 truncated surface as MALFORMED_CERT), strings go through
 * PEM detection (auto-strips headers + base64-decodes).
 *
 * @param {Uint8Array|Buffer|string} c - one certificate input
 * @returns {Object} parsed PqCertificate
 */
function parseCertInput(c) {
  if (typeof c === 'string') {
    return parseCertificateFromPemOrDer(c);
  }
  if (c instanceof Uint8Array || Buffer.isBuffer(c)) {
    return parseCertificate(c);
  }
  throw new TypeError('cert input must be Uint8Array/Buffer/string');
}

/**
 * Attach the resolution OID map to each certificate so generateCbom (S8)
 * resolves algorithm names through the caller's map instead of the default.
 * cbom.js reads `cert.oidMap` per certificate — no shared mutable state.
 *
 * @param {Array<Object>} certs - parsed certificates
 * @param {Map<string,string>} oidMap - caller OID map (Map or object)
 * @returns {Array<Object>} certificates carrying oidMap
 */
function withOidMap(certs, oidMap) {
  if (!(oidMap instanceof Map)) {
    return certs;
  }
  return certs.map((c) => Object.assign({}, c, { oidMap }));
}

/**
 * Parse a trust anchor input (TrustAnchor object, parsed PqCertificate,
 * PEM string, or DER bytes) into a TrustAnchor-like object with
 * { oid, publicKey, name?, serialNumber? }.
 *
 * @param {Object|string|Uint8Array|Buffer} anchor - Trust anchor input
 * @returns {Object} TrustAnchor object
 */
function parseTrustAnchor(anchor) {
  // Already a TrustAnchor object (from loadTrustAnchorsFromPem/Der or manual)
  if (anchor && typeof anchor === 'object' && anchor.oid && anchor.publicKey instanceof Uint8Array) {
    return anchor;
  }

  // Parsed certificate object (PqCertificate from parseCertificate)
  if (anchor && typeof anchor === 'object' && anchor.subjectPublicKeyInfo) {
    return {
      oid: anchor.subjectPublicKeyInfo.algorithm,
      publicKey: anchor.subjectPublicKeyInfo.publicKey,
      name: anchor.subject?.CN || anchor.subject?.O || 'trust-anchor',
      serialNumber: anchor.serialNumber,
      subject: anchor.subject,
      issuer: anchor.issuer,
    };
  }

  // PEM string
  if (typeof anchor === 'string') {
    const cert = parseCertificateFromPemOrDer(anchor);
    return {
      oid: cert.subjectPublicKeyInfo.algorithm,
      publicKey: cert.subjectPublicKeyInfo.publicKey,
      name: cert.subject?.CN || cert.subject?.O || 'trust-anchor',
      serialNumber: cert.serialNumber,
      subject: cert.subject,
      issuer: cert.issuer,
    };
  }

  // DER bytes
  if (anchor instanceof Uint8Array || Buffer.isBuffer(anchor)) {
    const cert = parseCertificate(anchor);
    return {
      oid: cert.subjectPublicKeyInfo.algorithm,
      publicKey: cert.subjectPublicKeyInfo.publicKey,
      name: cert.subject?.CN || cert.subject?.O || 'trust-anchor',
      serialNumber: cert.serialNumber,
      subject: cert.subject,
      issuer: cert.issuer,
    };
  }

  throw new TypeError('trust anchor must be TrustAnchor object, PEM string, or DER bytes');
}

/**
 * Coerce input into a certificate chain array of DER bytes.
 * Accepts: Uint8Array, Buffer, string (PEM/DER), or array of any of the above.
 * A plain string that is valid PEM is parsed as a single cert; otherwise treated as DER.
 *
 * @param {Uint8Array|Buffer|string|Array} input - Raw cert chain or single cert.
 * @returns {Array<Uint8Array>} Array of DER Uint8Array entries.
 */
export function normalizeCertBundle(input) {
  if (Array.isArray(input)) {
    return input.map((c) => {
      if (c instanceof Uint8Array || Buffer.isBuffer(c) || typeof c === 'string') {
        return c;
      }
      throw new TypeError('chain element must be Uint8Array/Buffer/string');
    });
  }

  if (typeof input === 'string') {
    // PEM bundle: split into individual PEM blocks so each cert is counted
    // separately for maxDepth and chain walking. S9-27 / PEM-multi-cert paths.
    const pemBlocks = input.match(PEM_CERT_BLOCK_RE);
    if (pemBlocks && pemBlocks.length > 0) {
      return pemBlocks;
    }
    return [input];
  }

  if (input instanceof Uint8Array || Buffer.isBuffer(input)) {
    const buf = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (buf.length > 0 && buf[0] === 0x30) {
      // DER bundle (or single DER cert): split at TLV boundaries so a
      // concatenated leaf+root bundle is seen as multiple certificates.
      return splitDerBundle(buf);
    }
    return [input];
  }

  throw new TypeError('verifyPqChain input must be DER/PEM bytes or array of same');
}

/**
 * Split concatenated DER certificates at TLV boundaries using the certified
 * S1 readTlv reader. Returns one element per cert; falls back to [whole]
 * when nothing splits.
 *
 * @param {Uint8Array} der - DER bytes (one or more concatenated certs)
 * @returns {Uint8Array[]} individual DER cert byte arrays
 */
function splitDerBundle(der) {
  const certs = [];
  let offset = 0;
  while (offset < der.length) {
    if (der[offset] !== 0x30) break; // not a SEQUENCE — stop cleanly
    let tlv;
    try {
      tlv = readTlv(der, offset);
    } catch {
      break; // malformed tail — stop rather than crash
    }
    if (tlv.tag !== 0x30) break;
    const certEnd = offset + tlv.totalLen;
    if (certEnd > der.length) break;
    certs.push(der.subarray(offset, certEnd));
    offset = certEnd;
  }
  if (certs.length === 0) {
    return [new Uint8Array(der)];
  }
  return certs;
}

/**
 * Top-level verification: one-call PQ certificate chain verification.
 *
 * @param {Uint8Array|Buffer|string|Array} rawCertChain - DER or PEM bytes of
 *   the full certificate chain (leaf first, intermediates, root last), or array.
 * @param {object} [opts={}] - Optional verification options.
 * @param {Array} [opts.trustAnchors=[]] - PQ certificate(s) trusted
 *   as anchors; each may be TrustAnchor object, DER (Uint8Array/Buffer), or PEM string.
 * @param {number} [opts.maxDepth=5] - Maximum intermediate certificates
 *   allowed in the chain. E11 surfaced when exceeded.
 * @param {Map} [opts.oidMap=DEFAULT_OID_MAP] - Maps algorithm OIDs to
 *   human-readable names; shadows DEFAULT_OID_MAP when provided.
 * @param {object} [opts.ctx] - FIPS 204 context bytes for ML-DSA contexts
 *   (0–255 bytes inclusive); also accepted as opts.ctx alias.
 * @param {Uint8Array[]} [opts.crls] - Certificate revocation lists (one per
 *   trust anchor), each a DER-encoded X.509 CRL.
 * @returns {object} PqVerificationResult — { verified, errors, chain, cbom }
 *   where errors is [] (empty) when verified === true.
 */
export function verifyPqChain(rawCertChain, opts = {}) {
  // ---- coerce input into a certificate chain ---------------------------
  let certChain = normalizeCertBundle(rawCertChain);
  if (!Array.isArray(certChain) || certChain.length === 0) {
    throw new TypeError(
      'verifyPqChain: chain must contain at least one certificate',
    );
  }

  // ---- options with defaults -------------------------------------------
  const maxDepth = Number(opts.maxDepth) || DEFAULT_MAX_DEPTH;
  const oidMap = opts.oidMap || DEFAULT_OID_MAP;
  const ctx = opts.ctx;
  const crls = opts.crls || [];

  // ---- type confusion guard (E19) --------------------------------------
  if (rawCertChain !== null && rawCertChain !== undefined) {
    if (
      typeof rawCertChain === 'number' ||
      typeof rawCertChain === 'boolean' ||
      (typeof rawCertChain === 'object' && !Buffer.isBuffer(rawCertChain) && !(rawCertChain instanceof Uint8Array) && !Array.isArray(rawCertChain) && typeof rawCertChain !== 'string')
    ) {
      throw new TypeError('verifyPqChain: input must be Uint8Array/Buffer/string/array');
    }
  }

  // Parse trust anchors - handle array, string (PEM), or Uint8Array (DER)
  let trustAnchors = opts.trustAnchors || [];
  if (!Array.isArray(trustAnchors)) {
    // allow single anchor as string/bytes/object
    trustAnchors = [trustAnchors];
  }
  trustAnchors = trustAnchors.map(parseTrustAnchor);

  // ---- resolve each certificate to its parsed structure ---------------
  const parsed = certChain.map(parseCertInput);

  // ---- maxDepth check: number of certificates in the chain ----
  // A chain with more certificates than maxDepth must fail with E11 before
  // any signature work. S9-13: leaf+root bundle with maxDepth:1 → E11.
  // maxDepth is the maximum number of certificates allowed in the chain
  // (the default 5 permits a 5-cert leaf→root path).
  if (parsed.length > maxDepth) {
    return {
      verified: false,
      errors: [`E11: chain depth ${parsed.length} exceeds maxDepth ${maxDepth}`],
      chain: parsed,
      cbom: generateCbom(withOidMap(parsed, oidMap)),
    };
  }

  // ---- basic chain walk: each cert must be signed by the next one ------
  const errors = [];
  const verifiedChain = [];

  for (let i = 0; i < parsed.length; i++) {
    const cert = parsed[i];
    // Determine who should verify this cert
    const issuerIdx = i + 1; // cert[i+1] is the issuer candidate
    if (issuerIdx >= parsed.length) {
      // Topmost cert in the bundle — must be a trust anchor
      if (trustAnchors.some((ta) => ta.serialNumber === cert.serialNumber)) {
        verifiedChain.push(cert);
        continue;
      }
      errors.push('E17: root cert not in trust anchors');
      verifiedChain.push(cert);
      continue;
    }

    const issuerCert = parsed[issuerIdx];
    // Use verifyChain: leaf chain[i] signed by chain[i+1]
    const chainResult = verifyChain(
      parsed[0], // leaf (first cert)
      parsed.filter((_, idx) => idx >= 1 && idx < i), // intermediates up to issuer
      [issuerCert], // anchor for this segment
      { ctx },
    );

    if (!chainResult.verified) {
      // first error wins
      if (!errors.some((e) => e.startsWith('E1'))) {
        errors.push(`E12: chain segment ${i} disconnected`);
      }
      verifiedChain.push(cert);
      continue;
    }

    verifiedChain.push(cert);
  }

  // ---- if we have at least one verified chain ending at a trust anchor --
  const allAnchorsValid = verifiedChain.length > 0 &&
    trustAnchors.some((ta) =>
      verifiedChain.some((c) => c.serialNumber === ta.serialNumber),
    );

  const result = {
    verified: allAnchorsValid && errors.length === 0,
    errors,
    chain: verifiedChain,
    cbom: generateCbom(withOidMap(verifiedChain, oidMap)),
  };

  return result;
}

/**
 * verifyCertificateChain — lower-level entry: validates a certificate
 * chain against explicit trust anchors with full options plumbing.
 *
 * @param {Uint8Array|Buffer|string} rawLeaf - Leaf (first) certificate.
 * @param {Uint8Array|Buffer|string[]} [rawIntermediates=[]] - Intermediate
 *   certificates between leaf and root.
 * @param {Uint8Array|Buffer|string[]} [rawTrustAnchors=[]] - Trust anchor(s).
 * @param {object} [opts={}] - Extra options (maxDepth, oidMap, ctx, crls).
 * @returns {object} PqVerificationResult — same shape as verifyPqChain.
 */
export function verifyCertificateChain(rawLeaf, rawIntermediates = [], rawTrustAnchors = [], opts = {}) {
  // Type validation for E19
  if (rawLeaf === null || rawLeaf === undefined ||
      typeof rawLeaf === 'number' || typeof rawLeaf === 'boolean' ||
      (typeof rawLeaf === 'object' && !Buffer.isBuffer(rawLeaf) && !(rawLeaf instanceof Uint8Array) && typeof rawLeaf !== 'string')) {
    throw new TypeError('verifyCertificateChain: rawLeaf must be DER/PEM bytes');
  }

  if (!Array.isArray(rawIntermediates)) {
    throw new TypeError('verifyCertificateChain: rawIntermediates must be an array');
  }

  if (!Array.isArray(rawTrustAnchors)) {
    throw new TypeError('verifyCertificateChain: rawTrustAnchors must be an array');
  }

  // Parse leaf
  let leaf;
  if (rawLeaf instanceof Uint8Array || Buffer.isBuffer(rawLeaf) || typeof rawLeaf === 'string') {
    leaf = parseCertificateFromPemOrDer(rawLeaf);
  } else {
    throw new TypeError('verifyCertificateChain: rawLeaf must be DER/PEM bytes');
  }

  // Parse intermediates
  const intermediates = (rawIntermediates || [])
    .map((c) => {
      if (c instanceof Uint8Array || Buffer.isBuffer(c) || typeof c === 'string') {
        return parseCertificateFromPemOrDer(c);
      }
      throw new TypeError('intermediate must be Uint8Array/Buffer/string');
    });

  // Parse trust anchors (support TrustAnchor objects, PEM, DER)
  const trustAnchors = (rawTrustAnchors || [])
    .map(parseTrustAnchor);

  const maxDepth = Number(opts.maxDepth) || 5;
  const oidMap = opts.oidMap || DEFAULT_OID_MAP;

  // Build the chain: leaf + intermediates
  const chain = [leaf, ...intermediates];

  // Use verifyChain from S6 core with trust anchors
  const result = verifyChain(leaf, intermediates, trustAnchors, opts);

  // Post-process into the standardized PqVerificationResult shape
  return {
    verified: result.verified,
    errors: result.errors || [],
    chain: [...intermediates, leaf], // rebuild for consumer friendliness
    cbom: generateCbom(withOidMap([leaf, ...intermediates], oidMap)),
  };
}

/**
 * normalizeAlgorithmName — map an OID to a human-readable algorithm name,
 * using the provided oidMap (falls back to DEFAULT_OID_MAP).
 *
 * @param {string} oid - DER OID string.
 * @param {Map} [map=DEFAULT_OID_MAP] - Optional override map.
 * @returns {string} Human-readable algorithm name.
 */
export function normalizeAlgorithmName(oid, map = DEFAULT_OID_MAP) {
  return map.get(oid) || oid;
}