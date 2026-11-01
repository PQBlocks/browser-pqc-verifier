#!/usr/bin/env node
/**
 * Example 2: Generate Cryptography Bill of Materials using @pqblocks/browser-pqc-verifier.
 */
import { generateCbom, normalizeCertBundle, parseCertificateFromPemOrDer } from '@pqblocks/browser-pqc-verifier';

const certPem = `-----BEGIN CERTIFICATE-----
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

function run() {
  const rawCerts = normalizeCertBundle(certPem);
  const certs = rawCerts.map(c => parseCertificateFromPemOrDer(c));
  const cbom = generateCbom(certs);
  if (!cbom || cbom.certCount !== 1) {
    throw new Error('CBOM generation failed');
  }
  console.log('CBOM generation: OK');
}

run();
