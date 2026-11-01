# Changelog

All notable changes to the `@pqblocks/browser-pqc-verifier` package are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-10-31

### Added
- Complete post-quantum X.509 certificate and chain verification engine for browser and Node.js environments.
- RFC 5280 path validation supporting root anchors, intermediate CAs, max depth limits, and basic constraints.
- Full support for NIST FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87) and NIST FIPS 205 (SLH-DSA) signatures.
- High-performance zero-copy ASN.1 DER parser for certificate and SubjectPublicKeyInfo structures.
- PEM and DER trust anchor loaders (`loadTrustAnchorsFromPem`, `loadTrustAnchorsFromDer`).
- Cryptography Bill of Materials (CBOM) generator supporting CycloneDX 1.5 JSON standard.
- Policy evaluation engine supporting NSA CNSA 2.0 and transitional hybrid profiles.
- CLI verification utility (`pqblocks-browser-verify`) for terminal and CI/CD pipelines.
- Comprehensive test suite with 280 test assertions and 100% pass rate.
