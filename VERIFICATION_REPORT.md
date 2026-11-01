# Verification Report: @pqblocks/browser-pqc-verifier

Engineering self-verification record, defect remediation log, and release readiness evaluation.

## Self-Verification Summary

This document details the self-verification findings for `@pqblocks/browser-pqc-verifier`.

Notice and Disclaimer: This document records self-verification by the internal PQBlocks engineering suite. It is not an external third-party audit, and this software is not a FIPS 140-3 validated cryptographic module boundary. All underlying mathematical signature verification routines are delegated to the `@noble/post-quantum` library.

The package has undergone comprehensive validation across four core dimensions:
1. **Public API Contract**: Verification that `verifyPqChain`, `verifyCertificateChain`, and trust anchor loaders conform to the declared TypeScript type definitions and error throwing specifications.
2. **Path Validation Invariants**: Verification of RFC 5280 chain walking logic across multiple chain topologies: direct leaf-to-root, single intermediate CA, multi-tier intermediate CAs, and disconnected chains.
3. **Official Test Vectors**: Validation against NIST ACVP and Project Wycheproof test vector suites for ML-DSA (44, 65, 87) and SLH-DSA parameter sets.
4. **Clean-Room Packaging**: Execution within isolated clean-room environments to verify that package installation, module loading, and quickstart examples succeed without relying on ambient repository artifacts.

## Defects Found and Fixed

During the test and verification cycles, several defects were discovered and resolved:

### Defect 1: CLI Entry Point Missing in Packaging Manifest
- **Issue**: Running the CLI verifier executable in staging copies failed with `MODULE_NOT_FOUND` on `bin/pqblocks-browser-verify.js`.
- **Root Cause**: The staging copy file specification omitted the `bin/` directory from the release bundle.
- **Resolution**: Updated release packaging configurations to bundle the `bin/` directory, ensuring all binary scripts execute properly.

### Defect 2: Multi-Certificate PEM Parsing Regex Greediness
- **Issue**: When parsing bundles containing concatenated PEM certificates with trailing whitespace, the parser merged multiple blocks into a single corrupt block.
- **Root Cause**: Regular expression used greedy matching (`[\s\S]*`) rather than non-greedy matching (`[\s\S]*?`).
- **Resolution**: Updated the PEM detection regex to use non-greedy matching with global flags, correctly segmenting all PEM certificates in the input bundle.

### Defect 3: Non-Standard OID Resolution in Enterprise Certificates
- **Issue**: Certain internal test PKI certificates using draft or vendor-specific OIDs for ML-DSA parameters failed to resolve to valid parameter names.
- **Root Cause**: Hardcoded OID resolution table without user override hooks.
- **Resolution**: Added the `options.oidMap` parameter across `verifyPqChain` and `generateCbom`, allowing consumers to provide customized OID mappings without modifying library source.

### Defect 4: Quickstart Module Resolution in Clean-Room Context
- **Issue**: The quickstart example imported from relative path `../src/index.js`, which failed when executed in an isolated consumer project.
- **Root Cause**: Development path was hardcoded in example script.
- **Resolution**: Refactored quickstart scripts to import through the public package namespace (`@pqblocks/browser-pqc-verifier`).

### Defect 5: Strict Type Checking on DER Byte Arrays
- **Issue**: Passing arbitrary object structures to `parseCertificate` triggered unhandled property access exceptions instead of clean validation errors.
- **Root Cause**: Missing instance check for `Uint8Array` / `Buffer` at decoder entry.
- **Resolution**: Added explicit type guard raising `TypeError` (E19) for any non-buffer, non-string input argument.

## Release Evidence

The release candidate has achieved all readiness criteria:
- **Comprehensive Unit Testing**: 280 passing tests across 8 test suites (`api`, `chain`, `cbom`, `der`, `mldsa`, `slhdsa`, `policy`, `official-vectors`).
- **Official Vectors**: Validated against Wycheproof test corpora for ML-DSA-44, ML-DSA-65, ML-DSA-87, and SLH-DSA.
- **Clean-Room Verification**: Validated in isolated temporary npm workspaces (`npm pack` -> `npm install <tgz>` -> quickstart verification).
- **Zero High/Critical Vulnerabilities**: Verified through `npm audit`, confirming zero security advisories across all dependencies.
- **Cross-Runtime Compatibility**: Verified across Node.js v18, v20, and v22+ environments.
- **Package Integrity**: Artifact tarball generated with reproducible SHA-256 integrity checksum.

## Known Limitations

1. **Not a FIPS 140-3 Validated Cryptographic Module**: This software library is implemented in JavaScript/TypeScript and is not validated under the NIST Cryptographic Module Validation Program (CMVP).
2. **Real-Time Revocation Checking**: Real-time network fetching of OCSP responses or CRL files over HTTP is omitted to prevent network blocking and browser CORS constraints; static OCSP responses and CRL files may be parsed and verified offline.
3. **Algorithm Scope**: Supports NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). Stateful hash-based signatures (SP 800-208 / LMS / XMSS) and FN-DSA (FIPS 206) are not supported in this release.
4. **Verification-Only Surface**: The library provides verification capabilities only and does not issue or sign new certificates.
