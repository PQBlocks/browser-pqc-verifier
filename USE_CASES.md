# Use Cases: @pqblocks/browser-pqc-verifier

Practical application scenarios and code patterns for client-side and server-side post-quantum certificate verification.

## Scenario 1: Browser-Side WebSocket TLS Certificate Verification

### Context
A secure financial web application connects to backend market data streams via WebSockets. To ensure the remote server is quantum-safe and resistant to active eavesdropping, the frontend browser application verifies the server's post-quantum certificate chain before finalizing the WebSocket connection.

### Implementation

```javascript
import {
  verifyPqChain,
  loadTrustAnchorsFromPem,
} from '@pqblocks/browser-pqc-verifier';

// Client holds pre-installed trusted root certificates
const trustedRootPem = `-----BEGIN CERTIFICATE-----
... (Trusted Corporate Root CA) ...
-----END CERTIFICATE-----`;

async function establishSecureWebSocket(serverCertChainPem) {
  // 1. Initialize trust anchors
  const anchors = loadTrustAnchorsFromPem(trustedRootPem);

  // 2. Verify server certificate chain before connecting
  const verification = await verifyPqChain(serverCertChainPem, {
    trustAnchors: anchors,
    maxDepth: 4,
  });

  if (!verification.verified) {
    throw new Error(`PQC Verification Failed: ${verification.errors.join(', ')}`);
  }

  console.log('Server certificate verified under ML-DSA: OK');
  console.log('Algorithms in chain:', verification.cbom.algorithms);

  // 3. Proceed with WebSocket connection
  const socket = new WebSocket('wss://stream.fintech.example/v1');
  return socket;
}

// Expected output on success:
// Server certificate verified under ML-DSA: OK
// Algorithms in chain: [ 'mldsa65' ]
```

## Scenario 2: Node.js API Gateway Ingestion and CBOM Extraction

### Context
An enterprise API gateway handles mTLS connections from partner financial institutions. Security compliance mandates automated generation of a Cryptography Bill of Materials (CBOM) for every partner certificate to feed into the corporate vulnerability management dashboard.

### Implementation

```javascript
import {
  generateCbom,
  generateCycloneDxCbom,
  normalizeCertBundle,
} from '@pqblocks/browser-pqc-verifier';

export function handlePartnerCertificate(clientCertPem) {
  // 1. Parse client certificate bundle
  const parsedCerts = normalizeCertBundle(clientCertPem);

  // 2. Extract CBOM metrics
  const cbom = generateCbom(parsedCerts);
  console.log('Certificates analyzed:', cbom.certCount);
  console.log('Quantum bit security level:', cbom.quantumBits);

  // 3. Generate CycloneDX 1.5 CBOM JSON for compliance pipeline
  const cycloneDxReport = generateCycloneDxCbom(parsedCerts);

  return {
    authorized: cbom.quantumBits >= 128,
    cbomJson: cycloneDxReport,
  };
}

// Expected output:
// Certificates analyzed: 2
// Quantum bit security level: 192
```

## Scenario 3: Automated CNSA 2.0 Policy Validation in CI/CD

### Context
A DevOps team enforces post-quantum security requirements in their automated deployment pipeline. All deployment manifests and container signature certificates must comply with NSA CNSA 2.0 post-quantum mandates.

### Implementation

```javascript
import {
  evaluateChainPolicy,
  PQC_POLICY_PROFILES,
} from '@pqblocks/browser-pqc-verifier';

export function validateDeploymentCertificates(bundlePem) {
  // Evaluate certificate chain against Strict CNSA 2.0 profile
  const report = evaluateChainPolicy(bundlePem, {
    profile: PQC_POLICY_PROFILES.STRICT_CNSA_2_0,
  });

  if (!report.compliant) {
    console.error('CNSA 2.0 Policy Violations:');
    report.violations.forEach((v) => console.error(` - ${v}`));
    return false;
  }

  console.log('CNSA 2.0 Validation: PASSED');
  console.log('Migration Readiness Score:', report.readinessScore);
  return true;
}

// Expected output for compliant ML-DSA-87 / ML-DSA-65 chain:
// CNSA 2.0 Validation: PASSED
// Migration Readiness Score: 100
```

## When to Use Something Else

While `@pqblocks/browser-pqc-verifier` provides comprehensive post-quantum certificate verification, other tools should be selected for specific architectures:

1. **Stateful Hash-Based Firmware Verification**: If your workflow verifies stateful hash-based signatures under NIST SP 800-208 (LMS / XMSS) for IoT firmware images, utilize dedicated SP 800-208 tooling; stateful hash algorithms are out of scope for this package.
2. **Unsupported Signature Primitives**: If your architecture requires Falcon / FN-DSA (FIPS 206) signature primitives, these are not supported by this package; consider upstream libraries for FN-DSA.
3. **Pure Raw Primitive Signing**: If your application requires raw mathematical key generation or signing of raw byte messages without X.509 certificates or chain walking, use `@noble/post-quantum` directly.
4. **Hardware Cryptographic Acceleration**: If your infrastructure requires hardware-isolated private key storage or CMVP Level 4 hardware security module validation, deploy FIPS-validated HSM appliances rather than client-side software.
