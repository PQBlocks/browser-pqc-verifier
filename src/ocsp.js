import { readTlv, decodeOid, encodeTlv, encodeSequence, encodeOctetString, encodeInteger, encodeOid } from './der.js';
import { extractSpki } from './spki.js';

export const OCSP_RESPONSE_STATUS = {
  SUCCESSFUL: 0,
  MALFORMED_REQUEST: 1,
  INTERNAL_ERROR: 2,
  TRY_LATER: 3,
  SIG_REQUIRED: 5,
  UNAUTHORIZED: 6
};

export const OCSP_OIDS = {
  BASIC_RESPONSE: '1.3.6.1.5.5.7.48.1.1',
  NONCE: '1.3.6.1.5.5.7.48.1.2',
  CRL: '1.3.6.1.5.5.7.48.1.3',
  RESPONSE: '1.3.6.1.5.5.7.48.1.4',
  NO_CHECK: '1.3.6.1.5.5.7.48.1.5',
  ARCHIVE_CUTOFF: '1.3.6.1.5.5.7.48.1.6',
  SERVICE_LOCATOR: '1.3.6.1.5.5.7.48.1.7',
  SHA256: '2.16.840.1.101.3.4.2.1',
  SHA1: '1.3.14.3.2.26'
};

export class OcspError extends Error {
  constructor(message, code = 'OCSP_ERROR') {
    super(message);
    this.name = 'OcspError';
    this.code = code;
  }
}

/**
 * Parse an RFC 6960 OCSP Response DER buffer.
 *
 * @param {Uint8Array} derBytes - Raw bytes of OCSPResponse
 * @returns {Object} Parsed OCSP response structure
 */
export function parseOcspResponse(derBytes) {
  if (!(derBytes instanceof Uint8Array) && !Buffer.isBuffer(derBytes)) {
    throw new TypeError('parseOcspResponse: derBytes must be Uint8Array or Buffer');
  }
  if (derBytes.length === 0) {
    throw new OcspError('Empty OCSP response bytes', 'E1');
  }

  const outer = readTlv(derBytes, 0);
  if (outer.tag !== 0x30) {
    throw new OcspError('Expected OCSPResponse SEQUENCE (tag 0x30)', 'E6');
  }

  let pos = 0;
  const val = outer.value;

  // 1. responseStatus ENUMERATED (0x0A)
  const statusTlv = readTlv(val, pos);
  if (statusTlv.tag !== 0x0A) {
    throw new OcspError('Expected responseStatus ENUMERATED', 'E6');
  }
  const responseStatus = statusTlv.value[0];
  pos += statusTlv.totalLen;

  if (responseStatus !== OCSP_RESPONSE_STATUS.SUCCESSFUL) {
    return {
      status: responseStatus,
      statusName: getOcspStatusName(responseStatus),
      successful: false
    };
  }

  // 2. responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
  let basicResponse = null;
  if (pos < val.length) {
    const respBytesTlv = readTlv(val, pos);
    if ((respBytesTlv.tag & 0xC0) === 0x80) { // [0]
      basicResponse = parseResponseBytes(respBytesTlv.value);
    }
  }

  return {
    status: responseStatus,
    statusName: 'successful',
    successful: true,
    basicResponse
  };
}

function parseResponseBytes(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return null;

  let pos = 0;
  const val = outer.value;

  // responseType OID
  const oidTlv = readTlv(val, pos);
  pos += oidTlv.totalLen;
  const responseType = decodeOid(oidTlv.value);

  // response OCTET STRING
  const octetTlv = readTlv(val, pos);
  const responseOctets = octetTlv.value;

  if (responseType === OCSP_OIDS.BASIC_RESPONSE) {
    return parseBasicOcspResponse(responseOctets);
  }

  return { responseType, raw: responseOctets };
}

function parseBasicOcspResponse(bytes) {
  const outer = readTlv(bytes, 0);
  if (outer.tag !== 0x30) return null;

  let pos = 0;
  const val = outer.value;

  // 1. tbsResponseData SEQUENCE
  const tbsTlv = readTlv(val, pos);
  pos += tbsTlv.totalLen;
  const tbs = parseTbsResponseData(tbsTlv.value);

  // 2. signatureAlgorithm AlgorithmIdentifier
  const sigAlgTlv = readTlv(val, pos);
  pos += sigAlgTlv.totalLen;
  const sigAlgOidTlv = readTlv(sigAlgTlv.value, 0);
  const signatureAlgorithm = decodeOid(sigAlgOidTlv.value);

  // 3. signature BIT STRING
  const sigTlv = readTlv(val, pos);
  pos += sigTlv.totalLen;
  const signature = sigTlv.value.subarray(1); // skip unused bits

  // 4. certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  const certs = [];
  if (pos < val.length) {
    const certsWrapper = readTlv(val, pos);
    if (certsWrapper.tag === 0xA0) {
      let cpos = 0;
      const cseq = readTlv(certsWrapper.value, 0);
      while (cpos < cseq.value.length) {
        const ctlv = readTlv(cseq.value, cpos);
        certs.push(new Uint8Array(cseq.value.subarray(cpos, cpos + ctlv.totalLen)));
        cpos += ctlv.totalLen;
      }
    }
  }

  return {
    tbsResponseData: tbs,
    signatureAlgorithm,
    signature,
    certs
  };
}

function parseTbsResponseData(bytes) {
  let pos = 0;

  // version [0] EXPLICIT Version DEFAULT v1
  let version = 1;
  const first = readTlv(bytes, pos);
  if (first.tag === 0xA0) {
    pos += first.totalLen;
  }

  // responderID (byName [1] or byKey [2])
  const responderTlv = readTlv(bytes, pos);
  pos += responderTlv.totalLen;
  const responderId = {
    type: (responderTlv.tag & 0x1F) === 1 ? 'byName' : 'byKey',
    value: responderTlv.value
  };

  // producedAt GeneralizedTime
  const producedAtTlv = readTlv(bytes, pos);
  pos += producedAtTlv.totalLen;
  const producedAtStr = Buffer.from(producedAtTlv.value).toString('ascii');

  // responses SEQUENCE OF SingleResponse
  const responsesTlv = readTlv(bytes, pos);
  const responses = [];
  let rpos = 0;
  while (rpos < responsesTlv.value.length) {
    const sTlv = readTlv(responsesTlv.value, rpos);
    responses.push(parseSingleResponse(sTlv.value));
    rpos += sTlv.totalLen;
  }

  return {
    version,
    responderId,
    producedAt: producedAtStr,
    responses
  };
}

function parseSingleResponse(bytes) {
  let pos = 0;

  // 1. certID CertID SEQUENCE
  const certIdTlv = readTlv(bytes, pos);
  pos += certIdTlv.totalLen;
  const certId = parseCertId(certIdTlv.value);

  // 2. certStatus CertStatus (CHOICE: good [0], revoked [1], unknown [2])
  const statusTlv = readTlv(bytes, pos);
  pos += statusTlv.totalLen;
  const statusTag = statusTlv.tag & 0x1F;

  let certStatus = { status: 'unknown' };
  if (statusTag === 0) {
    certStatus = { status: 'good' };
  } else if (statusTag === 1) {
    certStatus = { status: 'revoked', details: statusTlv.value };
  } else {
    certStatus = { status: 'unknown' };
  }

  // 3. thisUpdate GeneralizedTime
  const thisUpdateTlv = readTlv(bytes, pos);
  pos += thisUpdateTlv.totalLen;
  const thisUpdate = Buffer.from(thisUpdateTlv.value).toString('ascii');

  // 4. nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
  let nextUpdate = null;
  if (pos < bytes.length) {
    const nextTlv = readTlv(bytes, pos);
    if (nextTlv.tag === 0xA0) {
      const innerTime = readTlv(nextTlv.value, 0);
      nextUpdate = Buffer.from(innerTime.value).toString('ascii');
    }
  }

  return {
    certId,
    certStatus,
    thisUpdate,
    nextUpdate
  };
}

function parseCertId(bytes) {
  let pos = 0;

  // hashAlgorithm AlgorithmIdentifier
  const algTlv = readTlv(bytes, pos);
  pos += algTlv.totalLen;
  const hashAlgOid = decodeOid(readTlv(algTlv.value, 0).value);

  // issuerNameHash OCTET STRING
  const nameHashTlv = readTlv(bytes, pos);
  pos += nameHashTlv.totalLen;

  // issuerKeyHash OCTET STRING
  const keyHashTlv = readTlv(bytes, pos);
  pos += keyHashTlv.totalLen;

  // serialNumber INTEGER
  const serialTlv = readTlv(bytes, pos);
  const serialNumber = Buffer.from(serialTlv.value).toString('hex').toUpperCase();

  return {
    hashAlgorithm: hashAlgOid,
    issuerNameHash: nameHashTlv.value,
    issuerKeyHash: keyHashTlv.value,
    serialNumber
  };
}

function getOcspStatusName(code) {
  switch (code) {
    case OCSP_RESPONSE_STATUS.SUCCESSFUL: return 'successful';
    case OCSP_RESPONSE_STATUS.MALFORMED_REQUEST: return 'malformedRequest';
    case OCSP_RESPONSE_STATUS.INTERNAL_ERROR: return 'internalError';
    case OCSP_RESPONSE_STATUS.TRY_LATER: return 'tryLater';
    case OCSP_RESPONSE_STATUS.SIG_REQUIRED: return 'sigRequired';
    case OCSP_RESPONSE_STATUS.UNAUTHORIZED: return 'unauthorized';
    default: return 'unknown';
  }
}
