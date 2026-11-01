#!/usr/bin/env node
/**
 * Example 1: Verify a post-quantum certificate chain using @pqblocks/browser-pqc-verifier.
 */
import { verifyPqChain, loadTrustAnchorsFromPem } from '@pqblocks/browser-pqc-verifier';

const rootPem = `-----BEGIN CERTIFICATE-----
MIIDfzCCAmegAwIBAgIUaXvyueQOn6KG2FlckWS16jlMDM0wDQYJKoZIhvcNAQEL
BQAwTzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDVBRIFNoaWZ0IExhYnMxDTALBgNV
BAsMBFJvb3QxGTAXBgNVBAMMEFBRIFNoaWZ0IFJvb3QgQ0EwHhcNMjYxMDIxMjAy
MTM4WhcNMzYxMDE4MjAyMTM4WjBPMQswCQYDVQQGEwJVUzEWMBQGA1UECgwNUFEg
U2hpZnQgTGFiczENMAsGA1UECwwEUm9vdDEZMBcGA1UEAwwQUFEgU2hpZnQgUm9v
dCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANXktGV5TGFc7P8k
Mf6h0WKnFDYYyuxOgVdtTO/EfrcZk8azHMutQVAB4MjmWGIFZ/DwhazfoML19vfN
qTaYswix/qqXu/q9vz+A7pjssCBiVcRjhiW5grBoYIxiewrekxWVyYTPTy+U25K7
CiJapzTHXRq9ZnBFd6NFqisqkf1BM4YUcXRvwnHFKO+U9FN14DfoJb9CnVu5EYf+
SL+xNy0H/7Nw8WMHufbDwZyX30ljxaUWP92ANQ884Z+Ll5AhPczQ4LejSpxG2FeH
FWt9oq7af5fTcIvJ0BYrr70YQZVISZOad69inVlGRX766uKz92QvjDI0/n9eCXD2
XS6rklcCAwEAAaNTMFEwHQYDVR0OBBYEFApW3+CLkmy2FAkfEw4W8ppbQt8AMB8G
A1UdIwQYMBaAFApW3+CLkmy2FAkfEw4W8ppbQt8AMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAMUWJajst0LhvJNmfw9lcr1VjV1qAZG+viECKu/L
nUbaRy+fHT455ORUiVg9PuMQlwzDcju0hdl7+Z1ysM+zbl8pupUERa0bbLRfFtqo
4PaCLZp8NcsK0zj7jqEWagdGBiSnmnpZpThYWTdhhaDUCkESV8KknqirRslWm+F8
i9vuREduLDYde7GdddAuILpHEOEKtpxVNCM9Hgm6DFqaTKOHsB3R0fmdQayQtVmS
ZNtf40Lc7nEhTZUxMX0vnGBbQGTQ3NQYYdJ0WCfWtmE1V/VpJGkc4apuC2OEeg/6
stARzsnt45ogfPN8UVWOYuGYw90pdmqSkwt8bxMOqyfnLiM=
-----END CERTIFICATE-----`;

const leafPem = `-----BEGIN CERTIFICATE-----
MIIDcjCCAlqgAwIBAgIUF6wiL3fubBQoyrb2+Y8r360WxF0wDQYJKoZIhvcNAQEL
BQAwTzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDVBRIFNoaWZ0IExhYnMxDTALBgNV
BAsMBFJvb3QxGTAXBgNVBAMMEFBRIFNoaWZ0IFJvb3QgQ0EwHhcNMjYxMDIxMjAy
MTM4WhcNMjkwMTIzMjAyMTM4WjBTMQswCQYDVQQGEwJVUzEWMBQGA1UECgwNUFEg
U2hpZnQgTGFiczEMMAoGA1UECwwDVExTMR4wHAYDVQQDDBVsZWFmMS5wcXNoaWZ0
LmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClsu2MWjiQ
Q/7gXfyjpWXASTVQQnf5Ik4gODDMPrtwGp+lHhrGvPbWs3SGENzZcMuShvs0tW4U
mSqqlk7DQRIYIFps7pWlhXBhnn8W1YeLzpXsWasRyBcO2u/YTe0v9BFZBUjs7dEF
4Ug5rjrOMgOH2WYWhkK/odqqYrjoIh7ONG343ezF31kRSKgRzVr2V9J1Ga8nIUUh
/kjiNwUUV5bRoA/6vKbsCmtAPZlj/qVNKgnidkTAa4JnxpUWtXSJ+wEQ+WRoEheH
2GrFTAIzVJouUkibD/MkUvG19hOo3N0uNl9gxgB/PaZ1Lb61fEUGFBmGIsfm3NE0
ZGz+VvDaFhnxAgMBAAGjQjBAMB0GA1UdDgQWBBTAcEMqZCmrfd0qrvGXQ4P1tcsE
aDAfBgNVHSMEGDAWgBQKVt/gi5JsthQJHxMOFvKaW0LfADANBgkqhkiG9w0BAQsF
AAOCAQEAsAweu9CwrUOJPbYU9yGWMcduMscPECcZDIT9NjFedpo9a/aNobbfr2/x
h2ZOoZEGQRioivRslDNh2gR/qddyxZiPinWGTSuGx6r4T2Fekb33z695zt/abGkx
axKlmKSuVXDoL3OFZHmUm1HB+OWZDNanJPCW40GHsX2IsWmnbIrOROT6O8UIBP0S
1HlgPfry9ebrcqmO1osNqTdjzvQX69vMSCPDAXmOUqkQFlVtUrbBfzyAf9ACQzc6
CZZEG4l4rTUZc6Tg/YuBp6iBPVk1+QH9sK0HGbVlkJzPv63oz+V5PhwLMfdn2e8Y
Neo2pcLpdJ8f2xxiFjvsn3eUSAuZwA==
-----END CERTIFICATE-----`;

async function run() {
  const anchors = loadTrustAnchorsFromPem(rootPem);
  const chainPem = leafPem + '\n' + rootPem;
  const result = await verifyPqChain(chainPem, { trustAnchors: anchors });
  if (!result.verified) {
    throw new Error('Verification failed: ' + result.errors.join(', '));
  }
  console.log('Certificate chain verification: OK');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
