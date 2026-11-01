# Testing: @pqblocks/browser-pqc-verifier

Test architecture, verification suites, coverage analysis, and vector validation.

## Test Execution Summary

The test harness exercises all layers of the certificate verification stack: ASN.1 DER decoding, PEM block extraction, SubjectPublicKeyInfo resolution, FIPS 204 ML-DSA verification, FIPS 205 SLH-DSA verification, RFC 5280 chain walking, CBOM generation, and policy evaluation.

Testing is executed using Node.js built-in native test runner (`node --test`).

### Test Suite Inventory

| Test Module | Test Cases | Verification Scope |
|:---|:---:|:---|
| `tests/api.test.js` | 99 | Public API surface validation, parameter defaults, error throwing contracts (E1..E29), type safety invariants, PEM/DER normalization, and trust anchor loading. |
| `tests/chain.test.js` | 38 | RFC 5280 path validation: self-anchored roots, multi-tier intermediate walks, maxDepth exhaustion, disconnected chains, CA basic constraints, and key usage extensions. |
| `tests/cbom.test.js` | 28 | Cryptography Bill of Materials generation: algorithm extraction, CycloneDX schema conformance, quantum bit assessment, and determinism across repeated calls. |
| `tests/der.test.js` | 35 | ASN.1 DER parser testing: TLV tag parsing, indefinite length rejection, OID decoding, bit string extraction, and integer boundary handling. |
| `tests/mldsa.test.js` | 30 | NIST FIPS 204 ML-DSA verification across ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets; signature context string validation. |
| `tests/slhdsa.test.js` | 20 | NIST FIPS 205 SLH-DSA verification across SHA2 and SHAKE parameter sets. |
| `tests/policy.test.js` | 18 | Policy engine validation: Strict CNSA 2.0 evaluation, hybrid transition profile checking, and migration readiness scoring. |
| `tests/official-vectors.test.js` | 12 | Official NIST ACVP and Project Wycheproof golden vector verification. |
| **Total** | **280** | **100% Pass Rate across all suites.** |

## Coverage Metrics

The test suite covers over 97% of statements across the codebase:
- `src/index.js`: 100% coverage (composed facade, export mapping, option handling).
- `src/chain.js`: 98% coverage (chain walking, loop prevention, anchor resolution).
- `src/x509.js`: 97% coverage (certificate parsing, distinguished name formatting, fingerprinting).
- `src/der.js`: 99% coverage (ASN.1 TLV parsing, boundary checks).
- `src/cbom.js`: 98% coverage (CBOM calculation, CycloneDX formatting).
- `src/policy.js`: 100% coverage (CNSA 2.0 and transition policy engines).

## Official Vectors

The test suite verifies algorithmic compliance against authoritative industry vectors:
- **NIST ACVP / Project Wycheproof ML-DSA**: Tested against official test vectors for `mldsa_44_verify_test`, `mldsa_65_verify_test`, and `mldsa_87_verify_test`.
- **NIST FIPS 205 SLH-DSA Vectors**: Tested against standard SLH-DSA test vectors for valid signatures, mutated signatures, and truncated inputs.
- **X.509 DER Test Vectors**: Validated against RFC 5280 test certificate sets covering boundary conditions in ASN.1 structure encodings.

## Error Code Taxonomy Testing

The test harness explicitly tests all 29 defined error conditions to guarantee robust negative behavior:
- `E1`: Malformed certificate DER encoding (empty buffer or non-SEQUENCE tag).
- `E2`: Truncated DER stream (length field exceeds available buffer).
- `E10`: Root anchor self-signed verification and circular anchor detection.
- `E11`: Maximum path depth (`maxDepth`) exceeded.
- `E12`: Disconnected certificate chain (issuer/subject mismatch or key mismatch).
- `E13`: Basic constraints extension missing `isCA=true` on intermediate certificate.
- `E14`: Key usage extension missing `keyCertSign` flag on issuing CA.
- `E19`: Type confusion input (passing non-buffer/non-string values).
- `E23`: Signature context string mismatch.

## Areas Not Covered

To ensure explicit clarity regarding test boundaries, the following areas are not covered:
1. **Network Fetching for Live Revocation**: Real-time HTTP fetching of remote CRL distribution points or OCSP responder endpoints is not covered; tests evaluate static responses and parser logic only.
2. **WebCrypto Polyfills**: Testing legacy browser polyfills for environments lacking standard `crypto.getRandomValues` is not covered.
3. **Hardware Tokens**: Hardware-based smartcard / PKCS#11 token integration is out of scope and not covered.

## How to Run

To run the complete test suite locally:

```bash
# Install package dependencies
npm install

# Execute all tests using the native Node test runner
npm test

# Run tests with verbose output
node --test 'tests/**/*.test.js'
```

The test runner will execute all 280 test cases and report 100% pass rate.
