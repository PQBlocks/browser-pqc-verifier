# Security Notes: @pqblocks/browser-pqc-verifier

Security architecture, memory characteristics, dependency analysis, and threat model.

## What It Protects and What It Does Not

### Protections Provided
1. **Forgery Resistance in Quantum Era**:
   Verifies digital signatures adhering to NIST FIPS 204 (ML-DSA) and NIST FIPS 205 (SLH-DSA), which are mathematically resistant to quantum cryptanalysis (Shor's algorithm).
2. **RFC 5280 Path Validation**:
   Enforces structural certificate constraints including subject/issuer name matching, expiration dates, path length constraints, `isCA` basic constraints, and key usage extension flags to prevent unauthorized certificate delegation.
3. **Defense Against Malformed and Hostile ASN.1 Inputs**:
   The built-in DER decoder validates tag lengths, enforces strict DER canonical encodings, rejects indefinite length fields, and bounds recursion depth to protect against memory exhaustion denial-of-service.

### What It Does Not Protect
1. **Compromised Trust Anchors**:
   If a client application is provisioned with a compromised trust anchor (root CA), any forged certificate issued by that key will be accepted. Applications must safeguard their local trust store.
2. **Untrusted Client Host Environment**:
   If the browser or host Node.js process is compromised via cross-site scripting (XSS) or prototype pollution, validation outcomes can be manipulated in memory.
3. **Private Key Storage**:
   This library is a client-side verifier and does not manage or generate private signing keys.

## Runtime Memory and Cryptographic Hygiene

- **Constant-Time Cryptographic Primitives**:
  Low-level signature verification algorithms are executed by `@noble/post-quantum`, which utilizes constant-time operations for polynomial arithmetic, NTT transforms, and hashing routines to mitigate side-channel timing attacks.
- **Memory Management and Zeroization**:
  JavaScript engines (V8, SpiderMonkey) execute automated garbage collection without programmatic memory zeroization guarantees. However, because this package operates strictly as a verification library, it processes public certificates and public keys only; no private key material is ever handled or held in memory.
- **Randomness and Entropy Sources**:
  Where randomness or nonce generation is required for synthetic testing or ephemeral challenges, the library relies exclusively on the browser `crypto.getRandomValues()` API or Node.js `crypto.randomBytes()`.

## Dependencies and Security Posture

The package strictly minimizes external dependencies:
- `@noble/post-quantum`: Production-grade, zero-dependency pure JavaScript library audited by independent security firms for cryptographic correctness and constant-time behavior.

### Security Audit Status
Automated vulnerability scanning is performed via `npm audit` against the GitHub Advisory Database and npm registry. The dependency graph reports 0 vulnerabilities and 0 known security advisories. Continuous security scanning is integrated into build and release pipelines.
