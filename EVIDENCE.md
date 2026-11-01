# Evidence: @pqblocks/browser-pqc-verifier

Standards traceability matrix and method-to-code mapping.

## Primary Sources

The cryptographic standards, RFC specifications, and normative references implemented in `@pqblocks/browser-pqc-verifier` include:

1. **NIST FIPS 204**: *Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
   - Author: National Institute of Standards and Technology.
   - Date: August 2024.
   - DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
   - Scope: Specifications for ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature verification and parameter sets.

2. **NIST FIPS 205**: *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*.
   - Author: National Institute of Standards and Technology.
   - Date: August 2024.
   - DOI: [10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205)
   - Scope: Specifications for SLH-DSA parameter sets, verification routines, and public key encodings.

3. **IETF RFC 5280**: *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*.
   - Author: D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley, W. Polk.
   - Date: May 2008.
   - RFC: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
   - Scope: Path validation algorithm, basic constraints, key usage, name constraints, and extension handling.

4. **ITU-T Recommendation X.690**: *Information technology – ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)*.
   - Author: International Telecommunication Union.
   - Date: February 2021.
   - Scope: Governs ASN.1 DER Tag-Length-Value encoding rules and validation requirements.

5. **NSA Cybersecurity Advisory**: *Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)*.
   - Author: National Security Agency.
   - Date: September 2022.
   - Scope: PQC algorithm migration timelines, minimum quantum bit requirements, and protocol deployment rules.

6. **OWASP CycloneDX Specification**: *Cryptography Bill of Materials (CBOM) Standard v1.5*.
   - Author: OWASP Foundation.
   - Scope: JSON schema definitions for reporting cryptographic assets, dependencies, and algorithm postures.

## Method-to-Code Map

The following matrix documents the relationship between formal standards and their implementing source modules:

| Cryptographic Function | Specification Reference | Source Module | Implementing Function |
|:---|:---|:---|:---|
| Public Verification API | Unified Entry Point | `src/index.js` | `verifyPqChain` |
| PKIX Path Validation | RFC 5280 Section 6 | `src/chain.js` | `verifyCertificateChain` |
| X.509 Certificate Parser | RFC 5280 Section 4.1 | `src/x509.js` | `parseCertificate` |
| PEM Block Extraction | RFC 7468 | `src/pem.js` | `findPemBlocks`, `parsePem` |
| ASN.1 TLV Decoder | ITU-T X.690 Section 8 | `src/der.js` | `readTlv`, `decodeOid` |
| SPKI Extraction & OID Map | RFC 5280 Section 4.1.2.7 | `src/spki.js` | `extractSpki`, `resolveParams` |
| ML-DSA Verification Engine | NIST FIPS 204 Section 6 | `src/mldsa.js` | `verify` (via `@noble/post-quantum`) |
| SLH-DSA Verification Engine | NIST FIPS 205 Section 6 | `src/slhdsa.js` | `verifySlhDsa` |
| Trust Anchor Storage & Loading | RFC 5280 Section 6.1 | `src/trust-anchors.js` | `loadTrustAnchorsFromPem`, `loadTrustAnchorsFromDer` |
| CBOM Asset Extractor | CycloneDX 1.5 CBOM Standard | `src/cbom.js` | `generateCbom`, `generateCycloneDxCbom` |
| CNSA 2.0 Policy Evaluator | NSA CNSA 2.0 Advisory | `src/policy.js` | `evaluateChainPolicy`, `evaluateCnsa2Compliance` |
| X.509 Extension Processing | RFC 5280 Section 4.2 | `src/extensions.js` | `parseExtensions`, `checkHostNameConstraints` |
