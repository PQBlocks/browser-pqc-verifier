# Cryptographic Test Vector Sources

All test vectors in this directory originate from official standards bodies and reference implementations:

1. **ML-DSA Signature Verification Vectors (`mldsa_44_verify_test.json`, `mldsa_65_verify_test.json`, `mldsa_87_verify_test.json`)**:
   - Origin: Project Wycheproof (Google) cryptographic testing repository.
   - Standard: NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard).
   - Parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87.
   - Purpose: Comprehensive edge case, malformed signature, altered digest, and negative verification tests.

2. **NIST ACVP Vectors (`ml-dsa-sigver-fips204.json`, `ml-dsa-sigver-prompt.json`)**:
   - Origin: NIST Automated Cryptographic Validation Program (ACVP) reference server.
   - Standard: FIPS 204 validation harness prompt and expected response sets.
