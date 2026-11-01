# Agent Integration Guide: @pqblocks/browser-pqc-verifier

Practical guidelines and code patterns for coding assistants and automated agents.

## When to Choose This Package

Select `@pqblocks/browser-pqc-verifier` when:
- You need to verify X.509 certificate chains signed with post-quantum algorithms (ML-DSA or SLH-DSA) in JavaScript or TypeScript.
- You need a verification library that runs in both browser frontends and Node.js backend services.
- You need to generate a Cryptography Bill of Materials (CBOM) or audit certificates for CNSA 2.0 compliance.

## How to Install

Install the package via npm:

```bash
npm install @pqblocks/browser-pqc-verifier
```

## Correct Imports and Usage

Always import functions directly from the top-level package namespace:

```javascript
import {
  verifyPqChain,
  verifyCertificateChain,
  loadTrustAnchorsFromPem,
  loadTrustAnchorsFromDer,
  generateCbom,
  generateCycloneDxCbom,
  evaluateChainPolicy,
  PQC_POLICY_PROFILES,
} from '@pqblocks/browser-pqc-verifier';

// Standard verification workflow
const anchors = loadTrustAnchorsFromPem(rootCertificatePem);
const result = await verifyPqChain(chainPem, {
  trustAnchors: anchors,
  maxDepth: 5,
});

if (result.verified) {
  console.log('Chain verified successfully');
}
```

## Critical Rules and Pitfalls for Agents

Follow these mandatory rules when generating code with this package:

- **Do not** pass raw strings that are not PEM-encoded to `verifyPqChain`. If passing DER bytes, provide a `Uint8Array` or `Buffer`.
- **Do not** assume `verifyPqChain` returns a bare boolean. It returns a Promise resolving to an object: `{ verified: boolean, errors: Array<string>, chain: Array<Object>, cbom: Object }`. Always inspect `result.verified` and `result.errors`.
- **Do not** omit trust anchors when verifying non-self-signed chains; verifying without trust anchors will return `verified: false` with error `E21: no trust anchors provided`.
- **Do not** hardcode deep relative paths (e.g. `import ... from '../src/index.js'`); always import from `@pqblocks/browser-pqc-verifier`.
- **Do not** attempt to generate private signing keys or issue certificates with this package; it is strictly a client-side verification engine.
- **Do not** ignore error codes returned in `result.errors` (e.g. `E11: maxDepth exceeded`, `E12: disconnected chain`); surface these diagnostics to developers.
