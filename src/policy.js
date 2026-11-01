import { extractSpki, DEFAULT_OID_MAP, resolveParams } from './spki.js';

export const PQC_POLICY_PROFILES = {
  STRICT_CNSA_2_0: 'strict-cnsa-2.0',
  TRANSITION_HYBRID: 'transition-hybrid',
  FIPS_204_205_ONLY: 'fips-204-205-only',
  PERMISSIVE: 'permissive'
};

export const ALGORITHM_SECURITY_LEVELS = {
  // FIPS 204 (ML-DSA)
  'ML-DSA-44': { nistLevel: 2, quantumBits: 128, classicalBits: 128, type: 'pqc-lattice' },
  'ML-DSA-65': { nistLevel: 3, quantumBits: 192, classicalBits: 192, type: 'pqc-lattice' },
  'ML-DSA-87': { nistLevel: 5, quantumBits: 256, classicalBits: 256, type: 'pqc-lattice' },

  // FIPS 205 (SLH-DSA)
  'SLH-DSA-SHA2-128S': { nistLevel: 1, quantumBits: 128, classicalBits: 128, type: 'pqc-hash' },
  'SLH-DSA-SHA2-128F': { nistLevel: 1, quantumBits: 128, classicalBits: 128, type: 'pqc-hash' },
  'SLH-DSA-SHA2-192S': { nistLevel: 3, quantumBits: 192, classicalBits: 192, type: 'pqc-hash' },
  'SLH-DSA-SHA2-192F': { nistLevel: 3, quantumBits: 192, classicalBits: 192, type: 'pqc-hash' },
  'SLH-DSA-SHA2-256S': { nistLevel: 5, quantumBits: 256, classicalBits: 256, type: 'pqc-hash' },
  'SLH-DSA-SHA2-256F': { nistLevel: 5, quantumBits: 256, classicalBits: 256, type: 'pqc-hash' },

  // Classical (Legacy)
  'RSA-2048': { nistLevel: 0, quantumBits: 0, classicalBits: 112, type: 'classical' },
  'RSA-3072': { nistLevel: 0, quantumBits: 0, classicalBits: 128, type: 'classical' },
  'RSA-4096': { nistLevel: 0, quantumBits: 0, classicalBits: 152, type: 'classical' },
  'ECDSA-P256': { nistLevel: 0, quantumBits: 0, classicalBits: 128, type: 'classical' },
  'ECDSA-P384': { nistLevel: 0, quantumBits: 0, classicalBits: 192, type: 'classical' },
  'ED25519': { nistLevel: 0, quantumBits: 0, classicalBits: 128, type: 'classical' }
};

export class CryptoPolicyError extends Error {
  constructor(message, code = 'POLICY_VIOLATION') {
    super(message);
    this.name = 'CryptoPolicyError';
    this.code = code;
  }
}

/**
 * Evaluate a certificate chain against a specific PQC cryptographic policy profile.
 *
 * @param {Array<Object>} chain - Array of parsed certificates (leaf to root)
 * @param {Object} [options] - Policy options { profile?: string, minNistLevel?: number, disallowClassical?: boolean }
 * @returns {Object} Policy evaluation result { compliant: boolean, violations: string[], details: Object[] }
 */
export function evaluateChainPolicy(chain, options = {}) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new CryptoPolicyError('evaluateChainPolicy: chain must be a non-empty array of certificates');
  }

  const profile = options.profile || PQC_POLICY_PROFILES.PERMISSIVE;
  const minNistLevel = options.minNistLevel ?? getProfileMinNistLevel(profile);
  const disallowClassical = options.disallowClassical ?? (profile === PQC_POLICY_PROFILES.STRICT_CNSA_2_0 || profile === PQC_POLICY_PROFILES.FIPS_204_205_ONLY);

  const violations = [];
  const details = [];

  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const role = i === 0 ? 'leaf' : (i === chain.length - 1 ? 'root' : 'intermediate');
    const { oid } = extractSpki(cert);
    const resolvedName = resolveParams(oid, cert.oidMap) || oid;
    const algoUpper = resolvedName.toUpperCase();

    const algoInfo = ALGORITHM_SECURITY_LEVELS[algoUpper] || {
      nistLevel: isPqOid(oid) ? 2 : 0,
      quantumBits: isPqOid(oid) ? 128 : 0,
      classicalBits: 0,
      type: isPqOid(oid) ? 'pqc-unknown' : 'unknown'
    };

    const isClassical = algoInfo.type === 'classical' || algoInfo.nistLevel === 0;

    if (disallowClassical && isClassical) {
      violations.push(`Certificate ${i} (${role}) uses quantum-vulnerable classical algorithm ${algoUpper}, violating policy profile ${profile}`);
    }

    if (algoInfo.nistLevel < minNistLevel) {
      violations.push(`Certificate ${i} (${role}) algorithm ${algoUpper} provides NIST Level ${algoInfo.nistLevel}, below required minimum Level ${minNistLevel}`);
    }

    if (profile === PQC_POLICY_PROFILES.STRICT_CNSA_2_0) {
      const isCnsaApproved = algoUpper.includes('ML-DSA-65') || algoUpper.includes('ML-DSA-87') || algoUpper.includes('SLH-DSA-256') || algoUpper.includes('SLH-DSA-SHA2-256');
      if (!isCnsaApproved) {
        violations.push(`Certificate ${i} (${role}) algorithm ${algoUpper} is not approved under NSA CNSA 2.0 requirements`);
      }
    }

    details.push({
      index: i,
      role,
      algorithm: algoUpper,
      oid,
      nistLevel: algoInfo.nistLevel,
      type: algoInfo.type,
      compliant: violations.length === 0
    });
  }

  return {
    compliant: violations.length === 0,
    profile,
    violations,
    details
  };
}

function getProfileMinNistLevel(profile) {
  switch (profile) {
    case PQC_POLICY_PROFILES.STRICT_CNSA_2_0: return 3; // ML-DSA-65 is Level 3
    case PQC_POLICY_PROFILES.FIPS_204_205_ONLY: return 1;
    case PQC_POLICY_PROFILES.TRANSITION_HYBRID: return 1;
    case PQC_POLICY_PROFILES.PERMISSIVE: return 0;
    default: return 0;
  }
}

function isPqOid(oid) {
  if (!oid) return false;
  return (
    oid.startsWith('1.3.6.1.4.1.2.267.') || // Liboqs / hybrid experimental
    oid.startsWith('2.16.840.1.101.3.4.3.') // NIST PQC OIDs (ML-DSA, SLH-DSA)
  );
}

/**
 * Check if all certificates in a chain use exclusively post-quantum signatures.
 */
export function isPurePqChain(chain) {
  if (!Array.isArray(chain) || chain.length === 0) return false;
  for (const cert of chain) {
    const { oid } = extractSpki(cert);
    const resolved = resolveParams(oid, cert.oidMap);
    if (!resolved || !resolved.toLowerCase().includes('dsa')) {
      return false;
    }
  }
  return true;
}

/**
 * Calculate the overall post-quantum migration readiness score (0 - 100%) for a certificate hierarchy.
 */
export function calculateMigrationReadiness(chain) {
  if (!Array.isArray(chain) || chain.length === 0) return 0;

  let totalScore = 0;
  for (const cert of chain) {
    const { oid } = extractSpki(cert);
    const resolved = resolveParams(oid, cert.oidMap);
    if (!resolved) {
      totalScore += 0;
    } else {
      const lower = resolved.toLowerCase();
      if (lower.includes('ml-dsa-87') || lower.includes('slh-dsa-256')) totalScore += 100;
      else if (lower.includes('ml-dsa-65') || lower.includes('slh-dsa-192')) totalScore += 90;
      else if (lower.includes('ml-dsa-44') || lower.includes('slh-dsa-128')) totalScore += 75;
      else totalScore += 20;
    }
  }

  return Math.round(totalScore / chain.length);
}
