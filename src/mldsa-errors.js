/**
 * Errors thrown by the ML-DSA verify wrapper.
 * MldsaVerificationError carries a stable `code` field ('E9' = bad input type/length,
 * 'E23' = context mismatch) so callers can handle failures without parsing messages.
 */
export class MldsaVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MldsaVerificationError';
    this.code = null;
  }
}

/** Code 'E9' — type/length validation failure on verify() inputs. */
export function e9Error(message) {
  const err = new MldsaVerificationError(message);
  err.code = 'E9';
  return err;
}

/** Code 'E23' — context (FIPS 204 ctx) mismatch or invalid context. */
export function e23Error(message) {
  const err = new MldsaVerificationError(message);
  err.code = 'E23';
  return err;
}
