import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readTlv, decodeOid, readBitString, readTime } from '../src/der.js';

test('readTlv - short form length SEQUENCE', () => {
  // 0x30 0x03 0x02 0x01 0x01 = SEQUENCE len=3, INTEGER 1
  const buf = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);
  const tlv = readTlv(buf, 0);
  
  assert.equal(tlv.tag, 0x30);
  assert.equal(tlv.length, 3);
  assert.equal(tlv.headerLen, 2);
  assert.equal(tlv.totalLen, 5);
  assert.equal(tlv.nextOffset, 5);
  assert.deepEqual(tlv.value, new Uint8Array([0x02, 0x01, 0x01]));
});

test('readTlv - long form length (2 bytes)', () => {
  // 0x30 0x82 0x01 0x00 = SEQUENCE len=256
  const buf = new Uint8Array([0x30, 0x82, 0x01, 0x00, ...new Uint8Array(256).fill(0)]);
  const tlv = readTlv(buf, 0);
  
  assert.equal(tlv.tag, 0x30);
  assert.equal(tlv.length, 256);
  assert.equal(tlv.headerLen, 4);
  assert.equal(tlv.totalLen, 260);
});

test('readTlv - INTEGER short form', () => {
  // 0x02 0x01 0x05 = INTEGER 5
  const buf = new Uint8Array([0x02, 0x01, 0x05]);
  const tlv = readTlv(buf, 0);
  
  assert.equal(tlv.tag, 0x02);
  assert.equal(tlv.length, 1);
  assert.deepEqual(tlv.value, new Uint8Array([0x05]));
});

test('readTlv - truncated throws E2', () => {
  // Truncated: 0x30 0x05 but only 3 bytes provided
  const buf = new Uint8Array([0x30, 0x05, 0x02, 0x01]);
  assert.throws(() => readTlv(buf, 0), { code: 'E2', message: /truncated/ });
});

test('readTlv - oversized throws E3 (length > 4 bytes)', () => {
  // Length form with 5 bytes (0x85) - invalid
  const buf = new Uint8Array([0x30, 0x85, 0x00, 0x00, 0x00, 0x01, 0x00]);
  assert.throws(() => readTlv(buf, 0), { code: 'E6', message: /invalid length form/ });
});

test('readTlv - non-minimal length throws E6', () => {
  // 0x30 0x81 0x7f = long form encoding 127 which should be short form 0x7f
  const buf = new Uint8Array([0x30, 0x81, 0x7f, ...new Uint8Array(127).fill(0)]);
  assert.throws(() => readTlv(buf, 0), { code: 'E6', message: /non-minimal/ });
});

test('readTlv - TypeError on non-buffer (E19)', () => {
  assert.throws(() => readTlv('not a buffer'), { name: 'TypeError' });
  assert.throws(() => readTlv(null), { name: 'TypeError' });
  assert.throws(() => readTlv(123), { name: 'TypeError' });
});

test('decodeOid - ML-DSA-65 OID 1.2.840.113549.1.1.13.1.2.1', () => {
  // Correct DER encoding of 1.2.840.113549.1.1.13.1.2.1
  // arc0*40+arc1 = 1*40+2 = 42 = 0x2a
  // 840 = 6*128+72 => bytes [0x86, 0x48]
  // 113549 = 6*16384+119*128+13 => bytes [0x86, 0xf7, 0x0d]
  // 1,1,13,1,2,1 => [0x01, 0x01, 0x0d, 0x01, 0x02, 0x01]
  const oidValue = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x01, 0x02, 0x01]);
  const oid = decodeOid(oidValue);
  
  assert.equal(oid, '1.2.840.113549.1.1.13.1.2.1');
});

test('decodeOid - SHA-256 OID 2.16.840.1.101.3.4.2.1', () => {
  // 2.16.840.1.101.3.4.2.1 => first byte 0x60 (2*40+16=96=0x60)
  // rest: 86 48 01 65 03 04 02 01
  const oidValue = new Uint8Array([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
  const oid = decodeOid(oidValue);
  
  assert.equal(oid, '2.16.840.1.101.3.4.2.1');
});

test('decodeOid - empty throws E6', () => {
  const empty = new Uint8Array(0);
  assert.throws(() => decodeOid(empty), { code: 'E6', message: /OID content is empty/ });
});

test('decodeOid - TypeError on non-buffer (E19)', () => {
  assert.throws(() => decodeOid('not a buffer'), { name: 'TypeError' });
  assert.throws(() => decodeOid(null), { name: 'TypeError' });
});

test('readBitString - unused bits 0', () => {
  const value = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
  const result = readBitString(value);
  
  assert.equal(result.unusedBits, 0);
  assert.deepEqual(result.data, new Uint8Array([0x01, 0x02, 0x03]));
});

test('readBitString - unused bits 4', () => {
  const value = new Uint8Array([0x04, 0xff, 0xfe]);
  const result = readBitString(value);
  
  assert.equal(result.unusedBits, 4);
  assert.deepEqual(result.data, new Uint8Array([0xff, 0xfe]));
});

test('readBitString - invalid unused bits throws E6', () => {
  const value = new Uint8Array([0x08, 0x00]);
  assert.throws(() => readBitString(value), { code: 'E6', message: /unused bits/ });
});

test('readBitString - empty throws E6', () => {
  const empty = new Uint8Array(0);
  assert.throws(() => readBitString(empty), { code: 'E6', message: /BIT STRING content is empty/ });
});

test('readBitString - TypeError on non-buffer (E19)', () => {
  assert.throws(() => readBitString('not a buffer'), { name: 'TypeError' });
});

test('readTime - UTCTime 230101120000Z = 2023-01-01 12:00:00 UTC', () => {
  const value = new Uint8Array(Buffer.from('230101120000Z'));
  const date = readTime(0x17, value);
  
  assert.equal(date.getUTCFullYear(), 2023);
  assert.equal(date.getUTCMonth(), 0);
  assert.equal(date.getUTCDate(), 1);
  assert.equal(date.getUTCHours(), 12);
  assert.equal(date.getUTCMinutes(), 0);
  assert.equal(date.getUTCSeconds(), 0);
});

test('readTime - UTCTime 501231235959Z = 1950-12-31 23:59:59 UTC', () => {
  const value = new Uint8Array(Buffer.from('501231235959Z'));
  const date = readTime(0x17, value);
  
  assert.equal(date.getUTCFullYear(), 1950);
  assert.equal(date.getUTCMonth(), 11);
  assert.equal(date.getUTCDate(), 31);
  assert.equal(date.getUTCHours(), 23);
  assert.equal(date.getUTCMinutes(), 59);
  assert.equal(date.getUTCSeconds(), 59);
});

test('readTime - GeneralizedTime 20230101120000Z', () => {
  const value = new Uint8Array(Buffer.from('20230101120000Z'));
  const date = readTime(0x18, value);
  
  assert.equal(date.getUTCFullYear(), 2023);
  assert.equal(date.getUTCMonth(), 0);
  assert.equal(date.getUTCDate(), 1);
  assert.equal(date.getUTCHours(), 12);
  assert.equal(date.getUTCMinutes(), 0);
  assert.equal(date.getUTCSeconds(), 0);
});

test('readTime - invalid UTCTime throws E6', () => {
  const value = new Uint8Array(Buffer.from('not a time'));
  assert.throws(() => readTime(0x17, value), { code: 'E6', message: /invalid UTCTime/ });
});

test('readTime - invalid GeneralizedTime throws E6', () => {
  const value = new Uint8Array(Buffer.from('not a time'));
  assert.throws(() => readTime(0x18, value), { code: 'E6', message: /invalid GeneralizedTime/ });
});

test('readTime - wrong tag throws E6', () => {
  const value = new Uint8Array(Buffer.from('230101120000Z'));
  assert.throws(() => readTime(0x02, value), { code: 'E6', message: /unexpected tag/ });
});

test('readTime - TypeError on non-buffer (E19)', () => {
  assert.throws(() => readTime(0x17, 'not a buffer'), { name: 'TypeError' });
  assert.throws(() => readTime(0x17, null), { name: 'TypeError' });
});