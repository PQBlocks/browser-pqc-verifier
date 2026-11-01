# @pqblocks/browser-pqc-verifier

A high-performance post-quantum X.509 certificate and chain verification library designed for browser environments and Node.js runtimes.

## Why PQBlocks Browser PQC Verifier

As cryptographic infrastructure transitions toward post-quantum standards under CNSA 2.0 and NIST mandates, modern web applications face a severe client-side gap:
- Browsers and JavaScript engines currently lack native WebCrypto support for post-quantum public key infrastructure (PKI) standards.
- Low-level mathematical libraries (such as `@noble/post-quantum`) provide raw cryptographic signature verification (such as `ml_dsa65.verify`), but deliberately omit X.509 ASN.1/DER parsing, SubjectPublicKeyInfo (SPKI) extraction, RFC 5280 chain walks, basic constraints validation, trust anchor management, and Cryptography Bill of Materials (CBOM) generation.
- Traditional PKI libraries (such as `pkijs` or `node-forge`) rely on classical RSA and ECDSA algorithms and lack support for NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) parameter sets.

`@pqblocks/browser-pqc-verifier` bridges this divide. It delivers an end-to-end post-quantum PKIX chain validator that runs identically in modern web browsers (Chrome, Firefox, Safari, Edge) and Node.js environments without native compilation dependencies.

Key capabilities include:
- **Full Chain-Walk Verification**: Performs RFC 5280 validation including subject/issuer matching, validity periods, basic constraints (CA flag, path length), key usage flags, and trust anchor resolution.
- **Post-Quantum Signature Verification**: Implements FIPS 204 ML-DSA (parameter sets ML-DSA-44, ML-DSA-65, ML-DSA-87) and FIPS 205 SLH-DSA primitives powered by `@noble/post-quantum`.
- **Zero-Copy DER / PEM Parsing**: High-performance ASN.1 TLV parsing optimized for minimal memory allocations in browser thread contexts.
- **Automated CBOM Generation**: Generates Cryptography Bill of Materials compliant with the CycloneDX specification, reporting cryptographic algorithms, key lengths, and CNSA 2.0 migration readiness scores.

## Installation

Install the package via npm:

```bash
npm install @pqblocks/browser-pqc-verifier
```

### Compatibility Matrix
- **Browser Environments**: Modern evergreen browsers supporting ES2022 modules and `crypto.getRandomValues`.
- **Server Runtime**: Node.js v18.0.0 or higher.
- **Dependencies**: `@noble/post-quantum` (pure JavaScript, constant-time audited primitives).

## Usage

### 1. Basic Post-Quantum Certificate Chain Verification

```javascript
import {
  verifyPqChain,
  loadTrustAnchorsFromPem,
} from '@pqblocks/browser-pqc-verifier';

// Load trusted root certificate authority (PEM format)
const rootPem = `-----BEGIN CERTIFICATE-----
... (Root CA PEM) ...
-----END CERTIFICATE-----`;

// Load certificate chain to verify (Leaf + Intermediates + Root)
const chainPem = `-----BEGIN CERTIFICATE-----
... (Leaf Certificate PEM) ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
... (Root CA PEM) ...
-----END CERTIFICATE-----`;

// Parse trust anchors into the in-memory trust store
const anchors = loadTrustAnchorsFromPem(rootPem);

// Execute chain verification
const result = await verifyPqChain(chainPem, {
  trustAnchors: anchors,
  maxDepth: 5,
});

if (result.verified) {
  console.log('Certificate chain successfully verified!');
  console.log('CBOM Summary:', result.cbom);
} else {
  console.error('Verification failed:', result.errors);
}
```

### 2. Generating a Cryptography Bill of Materials (CBOM)

```javascript
import {
  generateCbom,
  generateCycloneDxCbom,
  normalizeCertBundle,
} from '@pqblocks/browser-pqc-verifier';

// Parse incoming certificate bundle (supports PEM, DER array, or raw Uint8Array)
const certs = normalizeCertBundle(chainPem);

// Generate structured CBOM
const cbom = generateCbom(certs);
console.log('Discovered algorithms:', cbom.algorithms);
console.log('Quantum bit strength:', cbom.quantumBits);

// Export standard CycloneDX 1.5 CBOM JSON
const cycloneDx = generateCycloneDxCbom(certs);
console.log('CycloneDX CBOM Components:', cycloneDx.components.length);
```

### 3. CNSA 2.0 Compliance Policy Enforcement

```javascript
import {
  evaluateChainPolicy,
  PQC_POLICY_PROFILES,
} from '@pqblocks/browser-pqc-verifier';

const compliance = evaluateChainPolicy(chainPem, {
  profile: PQC_POLICY_PROFILES.STRICT_CNSA_2_0,
});

console.log('CNSA 2.0 Compliant:', compliance.compliant);
console.log('Migration Readiness Score:', compliance.readinessScore);
```

## API Reference

### Core Verification Functions

#### `verifyPqChain(chainInput, options) -> Promise<VerificationResult>`
Top-level chain verification function.
- `chainInput`: String (PEM bundle), `Uint8Array` (DER sequence), or array of parsed certificate objects.
- `options.trustAnchors`: Array of trust anchors loaded via `loadTrustAnchorsFromPem` or `loadTrustAnchorsFromDer`.
- `options.maxDepth`: Maximum allowed intermediate certificate depth (default: `5`).
- `options.ctx`: Optional signature context byte string for ML-DSA (default: `""`).
- `options.oidMap`: Optional custom `Map<string, string>` mapping custom OIDs to algorithm parameter names.
- **Returns**: `Promise<{ verified: boolean, errors: Array<string>, chain: Array<Object>, cbom: Object }>`

#### `verifyCertificateChain(leaf, intermediates, roots, options) -> Promise<VerificationResult>`
Low-level PKIX path validation engine implementing RFC 5280 chain walking and signature verification against trust anchors.

### Trust Anchor Loaders

#### `loadTrustAnchorsFromPem(pemString) -> Array<TrustAnchor>`
Parses one or more PEM `CERTIFICATE` blocks from a string and returns an array of validated trust anchor records with public key bytes, algorithm OID, and subject distinguished name.

#### `loadTrustAnchorsFromDer(derBytes) -> Array<TrustAnchor>`
Extracts trust anchor definitions from concatenated or standalone DER-encoded X.509 certificate buffers.

### CBOM and Policy Engines

#### `generateCbom(certificates) -> Object`
Scans an array of certificates and extracts cryptographic properties: algorithm parameter names, key sizes, signature types, and overall quantum security level.

#### `generateCycloneDxCbom(certificates) -> Object`
Generates an OWASP CycloneDX 1.5 compliant Cryptography Bill of Materials suitable for software supply chain security audits.

#### `evaluateChainPolicy(chain, options) -> PolicyReport`
Evaluates certificate parameters against compliance profiles including `STRICT_CNSA_2_0`, `TRANSITIONAL_HYBRID`, and `FIPS_204_ONLY`.

## Limitations

- **Not FIPS 140-3 Validated**: This package is a pure JavaScript/TypeScript verification library and is not a FIPS 140-3 validated cryptographic module boundary.
- **Revocation Checking**: Version 1.0 supports static CRL and OCSP response parsing. Real-time online network fetching of OCSP responses over HTTP is deliberately omitted to maintain browser sandbox isolation and avoid CORS/CSP complications.
- **Standards Scope**: Supports FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). Classical RSA/ECDSA cross-validation is supported for transitional hybrid chains. Stateful hash-based signatures (SP 800-208 / LMS / XMSS) and FN-DSA (FIPS 206) are not supported in this release.
- **Private Key Operations**: Designed exclusively as a client-side verifier; does not generate private keys or sign certificate requests.

## Security Considerations

- **Audited Constant-Time Primitives**: All underlying mathematical operations for lattice and hash-based signature checks delegate directly to `@noble/post-quantum`, which features constant-time arithmetic to mitigate timing side channels.
- **Memory Management and Zeroization**: JavaScript runtimes (V8, SpiderMonkey, JavaScriptCore) employ garbage collection where heap memory cannot be immediately zeroized. Public keys, certificates, and nonces are processed in immutable `Uint8Array` buffers.
- **Hostile Input Defense**: The ASN.1 parser enforces strict bounds checking, tag length validation, and recursion limits to prevent denial-of-service via malformed, truncated, or cyclic ASN.1 structures.
- **Dependency Audit**: The package maintains zero native binary dependencies and passes automated security vulnerability audits with zero reported advisories.

## Verification

The correctness and robustness of `@pqblocks/browser-pqc-verifier` are verified through comprehensive automated testing:
- **Test Suite**: 280 test assertions across 2 test suites using the native Node.js test runner (`node --test`).
- **Official Vectors**: Tested against NIST ACVP and Project Wycheproof golden test vectors for ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
- **Detailed Verification Report**: Full defect logs, structural invariant checks, and release criteria are documented in [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md).
- **Performance Benchmarks**: Detailed latency analysis across varying chain sizes ($n=1$ to $n=100$) is documented in [BENCHMARKS.md](BENCHMARKS.md).

## Part of PQBlocks

`@pqblocks/browser-pqc-verifier` is part of the **PQBlocks** initiative—an open-source collection of modular, production-ready post-quantum cryptography tools and standards compliance libraries.
