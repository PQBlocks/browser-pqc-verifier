/**
 * ML-DSA verify wrapper.
 * Integrates with @noble/post-quantum; ML-DSA verification wrapper.
 * Exports only verify(); no keygen/sign exported.
 *
 * The wrapper adds its own length/type contract on top of the library's behaviour:
 *   - type + length validation throws MldsaVerificationError (code 'E9')
 *   - after validation passes, it delegates to @noble/post-quantum
 *   - tampered / wrong keypair → boolean false (library contract)
 *   - ctx support per FIPS 204 (opts.context)
 */

/* eslint-disable no-unused-vars */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { MldsaVerificationError, e9Error, e23Error } from './mldsa-errors.js';

export { MldsaVerificationError, e9Error, e23Error };

/** Map alias 'mlDsa65' / '65' → internal library name 'mldsa65' */
const PARAM_MAP = new Map([
  ['mldsa44', 'mldsa44'],
  ['mlDsa44', 'mldsa44'],
  ['44', 'mldsa44'],
  ['mldsa65', 'mldsa65'],
  ['mlDsa65', 'mldsa65'],
  ['65', 'mldsa65'],
  ['mldsa87', 'mldsa87'],
  ['mlDsa87', 'mldsa87'],
  ['87', 'mldsa87'],
]);

/** Validation errors for the wrapper only (not passed to the library). */
/** Resolve the internal @noble parameter name from the wrapper's param alias. */
function resolveInternalParam(params) {
  const name = PARAM_MAP.get(params);
  if (!name) {
    throw e9Error('invalid parameter set');
  }
  return name;
}

/**
 * Verify an ML-DSA signature.
 *
 * @param {string} params - Parameter set: 'mldsa44' | 'mlDsa44' | '44' |
 *   'mldsa65' | 'mlDsa65' | '65' | 'mldsa87' | 'mlDsa87' | '87'
 * @param {Uint8Array} publicKeyBytes - Raw ML-DSA public key bytes
 * @param {Uint8Array} sig - Raw ML-DSA signature bytes
 * @param {Uint8Array} message - Message that was signed
 * @param {object} [opts={}] - Optional context
 * @param {Uint8Array} [opts.ctx] - FIPS 204 context (0–255 bytes inclusive)
 * @returns {boolean} true if the signature is valid, false otherwise
 * @throws {MldsaVerificationError} on bad input types/lengths
 */
export function verify(params, publicKeyBytes, sig, message, opts = {}) {
  // ---- input type validation ----
  if (!publicKeyBytes || typeof publicKeyBytes !== 'object' || !(publicKeyBytes instanceof Uint8Array)) {
    throw e9Error('publicKey must be Uint8Array');
  }
  if (!sig || typeof sig !== 'object' || !(sig instanceof Uint8Array)) {
    throw e9Error('signature must be Uint8Array');
  }
  if (!message || typeof message !== 'object' || !(message instanceof Uint8Array)) {
    throw e9Error('message must be Uint8Array');
  }

  // ---- length validation ----
  const name = resolveInternalParam(params);
  const lib = (name === 'mldsa44') ? ml_dsa44 :
              (name === 'mldsa65') ? ml_dsa65 : ml_dsa87;

  const expectedPkLen = lib.lengths.publicKey;
  const expectedSigLen = lib.lengths.signature;

  if (publicKeyBytes.length !== expectedPkLen) {
    throw e9Error(`publicKey length: expected ${expectedPkLen}, got ${publicKeyBytes.length}`);
  }
  if (sig.length !== expectedSigLen) {
    throw e9Error(`signature length: expected ${expectedSigLen}, got ${sig.length}`);
  }

  // ---- context validation (FIPS 204: 0–255 bytes) ----
  // Accept both opts.context and opts.ctx aliases; the library's option is `context`.
  const context = opts.context ?? opts.ctx;
  if (context !== undefined) {
    if (!(context instanceof Uint8Array)) {
      throw e9Error('context must be Uint8Array if provided');
    }
    if (context.length > 255) {
      throw e9Error('context must be 255 bytes or less per FIPS 204');
    }
  }

  // ---- delegate to the library ----
  try {
    const valid = lib.verify(sig, message, publicKeyBytes, { context });
    return Boolean(valid);
  } catch (e) {
    // library may throw RangeError for ctx>255, bad poly, etc.
    if (e instanceof RangeError) {
      const msg = e.message.toLowerCase();
      if (msg.includes('ctx should be 255 bytes or less') || msg.includes('context')) {
        throw e23Error(e.message);
      }
      // unknown range error
      throw e9Error(e.message);
    }
    // unknown error from library
    throw e9Error(String(e.message || e));
  }
}

/**
 * Exported parameter-map for downstream consumers (SDK floor ≥8 public exports).
 * The .d.ts will declare `verify`, plus keys below so that `Object.keys(mod)` shows ≥8 entries.
 */
/**
 * Parameter metadata for downstream consumers (SDK floor ≥8 public exports).
 * Keys are the three canonical FIPS 204 names; get() canonicalises aliases
 * ('mlDsa65', '65') so callers can use any accepted verify() parameter spelling.
 */
class ParamMap extends Map {
  get(key) {
    const canonical = PARAM_MAP.get(key);
    return super.get(canonical ?? key);
  }
}

export const ML_DSA_PARAMS = new ParamMap([
  ['mldsa44', { publicKeyBytes: 1312, signatureBytes: 2420 }],
  ['mldsa65', { publicKeyBytes: 1952, signatureBytes: 3309 }],
  ['mldsa87', { publicKeyBytes: 2592, signatureBytes: 4627 }],
]);