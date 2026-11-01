import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f
} from '@noble/post-quantum/slh-dsa.js';

export const SLH_DSA_PARAMS = {
  // SHA-2 parameter sets
  'slh-dsa-sha2-128s': { impl: slh_dsa_sha2_128s, pkBytes: 32, sigBytes: 7856, nistLevel: 1, hash: 'SHA-256' },
  'slh-dsa-sha2-128f': { impl: slh_dsa_sha2_128f, pkBytes: 32, sigBytes: 17088, nistLevel: 1, hash: 'SHA-256' },
  'slh-dsa-sha2-192s': { impl: slh_dsa_sha2_192s, pkBytes: 48, sigBytes: 16224, nistLevel: 3, hash: 'SHA-384' },
  'slh-dsa-sha2-192f': { impl: slh_dsa_sha2_192f, pkBytes: 48, sigBytes: 35664, nistLevel: 3, hash: 'SHA-384' },
  'slh-dsa-sha2-256s': { impl: slh_dsa_sha2_256s, pkBytes: 64, sigBytes: 29792, nistLevel: 5, hash: 'SHA-512' },
  'slh-dsa-sha2-256f': { impl: slh_dsa_sha2_256f, pkBytes: 64, sigBytes: 49856, nistLevel: 5, hash: 'SHA-512' },
  // SHAKE parameter sets
  'slh-dsa-shake-128s': { impl: slh_dsa_shake_128s, pkBytes: 32, sigBytes: 7856, nistLevel: 1, hash: 'SHAKE-128' },
  'slh-dsa-shake-128f': { impl: slh_dsa_shake_128f, pkBytes: 32, sigBytes: 17088, nistLevel: 1, hash: 'SHAKE-128' },
  'slh-dsa-shake-192s': { impl: slh_dsa_shake_192s, pkBytes: 48, sigBytes: 16224, nistLevel: 3, hash: 'SHAKE-256' },
  'slh-dsa-shake-192f': { impl: slh_dsa_shake_192f, pkBytes: 48, sigBytes: 35664, nistLevel: 3, hash: 'SHAKE-256' },
  'slh-dsa-shake-256s': { impl: slh_dsa_shake_256s, pkBytes: 64, sigBytes: 29792, nistLevel: 5, hash: 'SHAKE-256' },
  'slh-dsa-shake-256f': { impl: slh_dsa_shake_256f, pkBytes: 64, sigBytes: 49856, nistLevel: 5, hash: 'SHAKE-256' }
};

export const SLH_DSA_OIDS = {
  '2.16.840.1.101.3.4.3.22': 'slh-dsa-sha2-128s',
  '2.16.840.1.101.3.4.3.23': 'slh-dsa-sha2-128f',
  '2.16.840.1.101.3.4.3.24': 'slh-dsa-sha2-192s',
  '2.16.840.1.101.3.4.3.25': 'slh-dsa-sha2-192f',
  '2.16.840.1.101.3.4.3.26': 'slh-dsa-sha2-256s',
  '2.16.840.1.101.3.4.3.27': 'slh-dsa-sha2-256f',
  '2.16.840.1.101.3.4.3.28': 'slh-dsa-shake-128s',
  '2.16.840.1.101.3.4.3.29': 'slh-dsa-shake-128f',
  '2.16.840.1.101.3.4.3.30': 'slh-dsa-shake-192s',
  '2.16.840.1.101.3.4.3.31': 'slh-dsa-shake-192f',
  '2.16.840.1.101.3.4.3.32': 'slh-dsa-shake-256s',
  '2.16.840.1.101.3.4.3.33': 'slh-dsa-shake-256f'
};

export class SlhdsaVerificationError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SlhdsaVerificationError';
    this.code = code;
  }
}

/**
 * Verify a Stateless Hash-Based Digital Signature (SLH-DSA, FIPS 205).
 *
 * @param {string} params - Parameter set identifier (e.g. 'slh-dsa-sha2-128f')
 * @param {Uint8Array} publicKeyBytes - Public key bytes
 * @param {Uint8Array} sig - Signature bytes
 * @param {Uint8Array} message - Message bytes
 * @param {Object} [options] - Verification options { ctx?: string|Uint8Array }
 * @returns {boolean} - True if signature is valid, false if invalid
 */
export function verifySlhDsa(params, publicKeyBytes, sig, message, options = {}) {
  if (!params || typeof params !== 'string') {
    throw new SlhdsaVerificationError('Invalid SLH-DSA parameter set name', 'E9');
  }

  const normalizedName = params.toLowerCase().replace(/_/g, '-');
  const paramConfig = SLH_DSA_PARAMS[normalizedName];

  if (!paramConfig) {
    throw new SlhdsaVerificationError(`Unknown SLH-DSA parameter set: ${params}`, 'E9');
  }

  if (!(publicKeyBytes instanceof Uint8Array)) {
    throw new SlhdsaVerificationError('Public key must be Uint8Array', 'E9');
  }

  if (publicKeyBytes.length !== paramConfig.pkBytes) {
    throw new SlhdsaVerificationError(
      `Invalid public key length for ${params}: expected ${paramConfig.pkBytes}, got ${publicKeyBytes.length}`,
      'E9'
    );
  }

  if (!(sig instanceof Uint8Array)) {
    throw new SlhdsaVerificationError('Signature must be Uint8Array', 'E9');
  }

  if (sig.length !== paramConfig.sigBytes) {
    return false;
  }

  if (!(message instanceof Uint8Array)) {
    throw new SlhdsaVerificationError('Message must be Uint8Array', 'E9');
  }

  let ctxBytes = new Uint8Array(0);
  const rawCtx = options.ctx !== undefined ? options.ctx : (options.context !== undefined ? options.context : '');

  if (typeof rawCtx === 'string') {
    ctxBytes = new TextEncoder().encode(rawCtx);
  } else if (rawCtx instanceof Uint8Array) {
    ctxBytes = rawCtx;
  } else {
    throw new SlhdsaVerificationError('Context must be string or Uint8Array', 'E9');
  }

  if (ctxBytes.length > 255) {
    throw new SlhdsaVerificationError('Context string length exceeds FIPS 205 limit of 255 bytes', 'E23');
  }

  try {
    const opts = ctxBytes.length > 0 ? { context: ctxBytes } : {};
    return Boolean(paramConfig.impl.verify(sig, message, publicKeyBytes, opts));
  } catch (err) {
    if (err instanceof SlhdsaVerificationError) throw err;
    return false;
  }
}

/**
 * Resolve SLH-DSA parameter config from an OID or algorithm name.
 */
export function resolveSlhDsaParams(oidOrName) {
  if (!oidOrName) return null;
  if (SLH_DSA_OIDS[oidOrName]) {
    const name = SLH_DSA_OIDS[oidOrName];
    return { name, ...SLH_DSA_PARAMS[name] };
  }
  const normalized = oidOrName.toLowerCase().replace(/_/g, '-');
  if (SLH_DSA_PARAMS[normalized]) {
    return { name: normalized, ...SLH_DSA_PARAMS[normalized] };
  }
  return null;
}
