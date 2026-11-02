import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { parseCertificate, pemToDer, parseCertificateFromPemOrDer } from '../src/x509.js';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';

// Helper: format name object like Node does (C=value\nO=value\... etc)
function formatNameToString(nameObj) {
  const parts = [];
  if (nameObj.C) parts.push(`C=${nameObj.C}`);
  if (nameObj.O) parts.push(`O=${nameObj.O}`);
  if (nameObj.OU) parts.push(`OU=${nameObj.OU}`);
  if (nameObj.CN) parts.push(`CN=${nameObj.CN}`);
  if (nameObj.L) parts.push(`L=${nameObj.L}`);
  if (nameObj.ST) parts.push(`ST=${nameObj.ST}`);
  if (nameObj.emailAddress) parts.push(`emailAddress=${nameObj.emailAddress}`);
  return parts.join('\n');
}

// E1: empty input throws
test('parseCertificate - empty input throws', () => {
  assert.throws(() => parseCertificate(new Uint8Array(0)), { code: 'E1' });
});

test('parseCertificate - null input throws', () => {
  assert.throws(() => parseCertificate(null), { name: 'TypeError' });
});

// E22: PEM input auto-handled
test('pemToDer - auto-detects PEM and converts to DER', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIDDzCCAfegAwIBAgIUaQNplowx1nK7vqIrv7SzCO8GxZgwDQYJKoZIhvcNAQEL\nBQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTAyMTIwMTM1M1oXDTI3\nMTAyMTIwMTM1M1owFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1zzxosV9y25YjJjfvTTT+Nl2sqdXRi4vUhC9\nfaLxA2oPxj7/2iQpJHccaIAHhRVu1zgm/3A36A/mL5cA3fcejOF6JAbc7IesIrpY\nYT8ux549XqxwW09GvdexXpl0rJACQsu1+tni5DA6AYyaQ1OOd/tY3eWrTf3VVSqx\nQmPDr5loLrFlBnYRsJLwERQHp0VmtkFjz4zWGG+9LdAhMXCTKsXdMQUTvKAzbtKo\ncLemmu9aVzMqTK2el89wjCn4yLVJWxuF620qOj/V8pfmVoELFHX03q0C4A97+MEY\nzVfkAa55Ni9Lhxbn9itygBw0LA0DNqPwMc6fQGrzU0JXlY6iVQIDAQABo1MwUTAd\nBgNVHQ4EFgQU3GCZ0c+QVgvCo8jOwUp3a6It0MowHwYDVR0jBBgwFoAU3GCZ0c+Q\nVgvCo8jOwUp3a6It0MowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAQEAmnEOoX++f1+I0U/8p1zANyemlToCmckZ7CklqJo/IxnUF6mXXeaMqC1xNQqN\nAsmVbKOAvRk53Skd22xL4IL86e3aIF+uQplM7RwjtKUB7sDpeznGLEnVyykNr3h0\nE52wtxQu8lBeL2Ozq7aFb/BvFVyS516RKKTrxBjQR9EO7j9AbRFBnRBtqiWv5aH/\nReGlh/3+BCRC234nNMqLabmxU9bmgLtUHEu11aDIBTSJshDQ0Oo4QpGWR+Jf2DUp\nvptV22ZwWHoU41vHPkWLzklhZZiSrH0BfgzhLggkmRe7PKvGPjFYuB6IW88KnrbD\nWt9nLXxwMnJcbDuCgVi+MjLaJQ==\n-----END CERTIFICATE-----\n';
  const der = pemToDer(pem);
  assert.ok(der.length > 0);
});

test('parseCertificateFromPemOrDer - converts PEM and returns parsed struct', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIDDzCCAfegAwIBAgIUaQNplowx1nK7vqIrv7SzCO8GxZgwDQYJKoZIhvcNAQEL\nBQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTAyMTIwMTM1M1oXDTI3\nMTAyMTIwMTM1M1owFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1zzxosV9y25YjJjfvTTT+Nl2sqdXRi4vUhC9\nfaLxA2oPxj7/2iQpJHccaIAHhRVu1zgm/3A36A/mL5cA3fcejOF6JAbc7IesIrpY\nYT8ux549XqxwW09GvdexXpl0rJACQsu1+tni5DA6AYyaQ1OOd/tY3eWrTf3VVSqx\nQmPDr5loLrFlBnYRsJLwERQHp0VmtkFjz4zWGG+9LdAhMXCTKsXdMQUTvKAzbtKo\ncLemmu9aVzMqTK2el89wjCn4yLVJWxuF620qOj/V8pfmVoELFHX03q0C4A97+MEY\nzVfkAa55Ni9Lhxbn9itygBw0LA0DNqPwMc6fQGrzU0JXlY6iVQIDAQABo1MwUTAd\nBgNVHQ4EFgQU3GCZ0c+QVgvCo8jOwUp3a6It0MowHwYDVR0jBBgwFoAU3GCZ0c+Q\nVgvCo8jOwUp3a6It0MowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAQEAmnEOoX++f1+I0U/8p1zANyemlToCmckZ7CklqJo/IxnUF6mXXeaMqC1xNQqN\nAsmVbKOAvRk53Skd22xL4IL86e3aIF+uQplM7RwjtKUB7sDpeznGLEnVyykNr3h0\nE52wtxQu8lBeL2Ozq7aFb/BvFVyS516RKKTrxBjQR9EO7j9AbRFBnRBtqiWv5aH/\nReGlh/3+BCRC234nNMqLabmxU9bmgLtUHEu11aDIBTSJshDQ0Oo4QpGWR+Jf2DUp\nvptV22ZwWHoU41vHPkWLzklhZZiSrH0BfgzhLggkmRe7PKvGPjFYuB6IW88KnrbD\nWt9nLXxwMnJcbDuCgVi+MjLaJQ==\n-----END CERTIFICATE-----\n';
  const result = parseCertificateFromPemOrDer(pem);
  assert.strictEqual(result.version, 3);
  assert.ok(result.serialNumber.length > 0);
  assert.ok(result.issuer.CN);
  assert.ok(result.subject.CN);
  assert.ok(result.signatureAlgorithm);
  assert.ok(result.signatureValue.length > 0);
});

// Parse all 25 corpus certificates and compare with node:crypto.X509Certificate
const certFiles = fs.readdirSync('tests/corpus')
  .filter(f => f.endsWith('.der') && f.startsWith('leaf'))
  .sort((a, b) => {
    const an = parseInt(a.match(/leaf(\d+)/)[1]);
    const bn = parseInt(b.match(/leaf(\d+)/)[1]);
    return an - bn;
  });

for (const certFile of certFiles) {
  const num = certFile.match(/leaf(\d+)/)[1];
  test(`parseCertificate corpus leaf${num} matches node:crypto`, () => {
    const der = new Uint8Array(fs.readFileSync(`tests/corpus/${certFile}`));
    const result = parseCertificate(der);
    
    // Also parse with node:crypto for comparison
    const pemFile = certFile.replace('.der', '.pem');
    const nodeCert = new X509Certificate(fs.readFileSync(`tests/corpus/${pemFile}`, 'utf8'));
    
    // Compare key fields
    assert.ok(result.version >= 2, `version ${result.version} too low for leaf${num}`);
    assert.strictEqual(result.serialNumber, nodeCert.serialNumber, `serialNumber mismatch for leaf${num}`);
    // Node's subject is formatted as "C=US\nO=...\nCN=...", our parser outputs object
    const ourSubject = formatNameToString(result.subject);
    assert.strictEqual(ourSubject, nodeCert.subject, `subject mismatch for leaf${num}: our=${JSON.stringify(ourSubject)} node=${JSON.stringify(nodeCert.subject)}`);
    // Node's issuer is also formatted string
    const ourIssuer = formatNameToString(result.issuer);
    assert.strictEqual(ourIssuer, nodeCert.issuer, `issuer mismatch for leaf${num}: our=${JSON.stringify(ourIssuer)} node=${JSON.stringify(nodeCert.issuer)}`);
    // validity - node uses validFrom/validTo, we use notBefore/notAfter (ISO strings)
    const notBefore = new Date(result.validity.notBefore);
    const notAfter = new Date(result.validity.notAfter);
    const nodeNotBefore = new Date(nodeCert.validFrom);
    const nodeNotAfter = new Date(nodeCert.validTo);
    assert.strictEqual(notBefore.getTime(), nodeNotBefore.getTime(), `notBefore mismatch for leaf${num}`);
    assert.strictEqual(notAfter.getTime(), nodeNotAfter.getTime(), `notAfter mismatch for leaf${num}`);
    const expectedSigAlg = nodeCert.signatureAlgorithmOid || '1.2.840.113549.1.1.11';
    assert.strictEqual(result.signatureAlgorithm, expectedSigAlg, `signatureAlgorithm mismatch for leaf${num}`);
    // Public key algorithm OID check
    const ourPubAlg = result.subjectPublicKeyInfo.algorithm.toString();
    assert.ok(ourPubAlg.includes('1.2.840.113549.1.1.1'), `publicKeyAlgorithm OID wrong: ${ourPubAlg}`);
    // signatureValue is not directly comparable, but check it exists
    assert.ok(result.signatureValue.length > 0, `signatureValue empty for leaf${num}`);
  });
}

// Test empty buffer throws E1
test('E1: empty buffer throws', () => {
  assert.throws(() => parseCertificate(new Uint8Array(0)), { code: 'E1' });
});

// Test TypeError on bad input type
test('E19: non-Buffer input throws TypeError', () => {
  assert.throws(() => parseCertificate('not a buffer'), { name: 'TypeError' });
  assert.throws(() => parseCertificate(null), { name: 'TypeError' });
  assert.throws(() => parseCertificate(123), { name: 'TypeError' });
});

// Test PEM conversion works
test('pemToDer works with PEM string', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIDDzCCAfegAwIBAgIUaQNplowx1nK7vqIrv7SzCO8GxZgwDQYJKoZIhvcNAQEL\nBQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTAyMTIwMTM1M1oXDTI3\nMTAyMTIwMTM1M1owFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1zzxosV9y25YjJjfvTTT+Nl2sqdXRi4vUhC9\nfaLxA2oPxj7/2iQpJHccaIAHhRVu1zgm/3A36A/mL5cA3fcejOF6JAbc7IesIrpY\nYT8ux549XqxwW09GvdexXpl0rJACQsu1+tni5DA6AYyaQ1OOd/tY3eWrTf3VVSqx\nQmPDr5loLrFlBnYRsJLwERQHp0VmtkFjz4zWGG+9LdAhMXCTKsXdMQUTvKAzbtKo\ncLemmu9aVzMqTK2el89wjCn4yLVJWxuF620qOj/V8pfmVoELFHX03q0C4A97+MEY\nzVfkAa55Ni9Lhxbn9itygBw0LA0DNqPwMc6fQGrzU0JXlY6iVQIDAQABo1MwUTAd\nBgNVHQ4EFgQU3GCZ0c+QVgvCo8jOwUp3a6It0MowHwYDVR0jBBgwFoAU3GCZ0c+Q\nVgvCo8jOwUp3a6It0MowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAQEAmnEOoX++f1+I0U/8p1zANyemlToCmckZ7CklqJo/IxnUF6mXXeaMqC1xNQqN\nAsmVbKOAvRk53Skd22xL4IL86e3aIF+uQplM7RwjtKUB7sDpeznGLEnVyykNr3h0\nE52wtxQu8lBeL2Ozq7aFb/BvFVyS516RKKTrxBjQR9EO7j9AbRFBnRBtqiWv5aH/\nReGlh/3+BCRC234nNMqLabmxU9bmgLtUHEu11aDIBTSJshDQ0Oo4QpGWR+Jf2DUp\nvptV22ZwWHoU41vHPkWLzklhZZiSrH0BfgzhLggkmRe7PKvGPjFYuB6IW88KnrbD\nWt9nLXxwMnJcbDuCgVi+MjLaJQ==\n-----END CERTIFICATE-----\n';
  const der = pemToDer(pem);
  assert.ok(der instanceof Uint8Array);
  assert.equal(der.length > 0, true);
});

test('parseCertificateFromPemOrDer - PEM input works', () => {
  const pem = '-----BEGIN CERTIFICATE-----\nMIIDDzCCAfegAwIBAgIUaQNplowx1nK7vqIrv7SzCO8GxZgwDQYJKoZIhvcNAQEL\nBQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTAyMTIwMTM1M1oXDTI3\nMTAyMTIwMTM1M1owFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1zzxosV9y25YjJjfvTTT+Nl2sqdXRi4vUhC9\nfaLxA2oPxj7/2iQpJHccaIAHhRVu1zgm/3A36A/mL5cA3fcejOF6JAbc7IesIrpY\nYT8ux549XqxwW09GvdexXpl0rJACQsu1+tni5DA6AYyaQ1OOd/tY3eWrTf3VVSqx\nQmPDr5loLrFlBnYRsJLwERQHp0VmtkFjz4zWGG+9LdAhMXCTKsXdMQUTvKAzbtKo\ncLemmu9aVzMqTK2el89wjCn4yLVJWxuF620qOj/V8pfmVoELFHX03q0C4A97+MEY\nzVfkAa55Ni9Lhxbn9itygBw0LA0DNqPwMc6fQGrzU0JXlY6iVQIDAQABo1MwUTAd\nBgNVHQ4EFgQU3GCZ0c+QVgvCo8jOwUp3a6It0MowHwYDVR0jBBgwFoAU3GCZ0c+Q\nVgvCo8jOwUp3a6It0MowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAQEAmnEOoX++f1+I0U/8p1zANyemlToCmckZ7CklqJo/IxnUF6mXXeaMqC1xNQqN\nAsmVbKOAvRk53Skd22xL4IL86e3aIF+uQplM7RwjtKUB7sDpeznGLEnVyykNr3h0\nE52wtxQu8lBeL2Ozq7aFb/BvFVyS516RKKTrxBjQR9EO7j9AbRFBnRBtqiWv5aH/\nReGlh/3+BCRC234nNMqLabmxU9bmgLtUHEu11aDIBTSJshDQ0Oo4QpGWR+Jf2DUp\nvptV22ZwWHoU41vHPkWLzklhZZiSrH0BfgzhLggkmRe7PKvGPjFYuB6IW88KnrbD\nWt9nLXxwMnJcbDuCgVi+MjLaJQ==\n-----END CERTIFICATE-----\n';
  const result = parseCertificateFromPemOrDer(pem);
  assert.ok(result.version > 0);
  assert.ok(result.serialNumber.length > 0);
  assert.ok(result.subject.CN);
});

// Also test the root CA cert
test('parseCertificate root CA matches node:crypto', () => {
  const der = new Uint8Array(fs.readFileSync('tests/corpus/root.der'));
  const result = parseCertificate(der);
  
  const nodeCert = new X509Certificate(fs.readFileSync('tests/corpus/root.pem', 'utf8'));
  
  assert.ok(result.version >= 2);
  assert.strictEqual(result.serialNumber, nodeCert.serialNumber);
  const ourSubject = formatNameToString(result.subject);
  assert.strictEqual(ourSubject, nodeCert.subject);
  const ourIssuer = formatNameToString(result.issuer);
  assert.strictEqual(ourIssuer, nodeCert.issuer);
  const notBefore = new Date(result.validity.notBefore);
  const notAfter = new Date(result.validity.notAfter);
  const nodeNotBefore = new Date(nodeCert.validFrom);
  const nodeNotAfter = new Date(nodeCert.validTo);
  assert.strictEqual(notBefore.getTime(), nodeNotBefore.getTime());
  assert.strictEqual(notAfter.getTime(), nodeNotAfter.getTime());
  const expectedRootSigAlg = nodeCert.signatureAlgorithmOid || '1.2.840.113549.1.1.11';
  assert.strictEqual(result.signatureAlgorithm, expectedRootSigAlg);
  const ourPubAlg = result.subjectPublicKeyInfo.algorithm.toString();
  assert.ok(ourPubAlg.includes('1.2.840.113549.1.1.1'), `publicKeyAlgorithm OID wrong: ${ourPubAlg}`);
  assert.ok(result.signatureValue.length > 0);
});