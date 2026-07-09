/**
 * Minimal, dependency-free X.509 DER parser for on-device identity checks.
 *
 * The React Native native module exposes only the raw DER of the peer leaf
 * certificate (no parsed subjectAltName), so on that path the library must parse
 * the certificate itself to recover the identity material it needs for hostname
 * verification. This parser extracts exactly two things from a leaf certificate:
 *
 *   - the subjectAltName dNSName and iPAddress entries, and
 *   - the subject Common Name (used only as a legacy fallback).
 *
 * It is deliberately small: it walks the definite-length DER TLV structure of an
 * X.509 v3 certificate, never executes signatures, and treats any malformed or
 * unexpected input as a parse failure (returns undefined / empty) so the caller
 * can fail closed. It is NOT a general-purpose ASN.1 library.
 *
 * Reference structure (RFC 5280):
 *   Certificate       ::= SEQUENCE { tbsCertificate, sigAlg, sigValue }
 *   TBSCertificate    ::= SEQUENCE { [0] version?, serial, sigAlg, issuer,
 *                                    validity, subject, subjectPKInfo, ...,
 *                                    [3] extensions? }
 *   Extension         ::= SEQUENCE { extnID OID, critical BOOLEAN?, extnValue OCTET STRING }
 *   subjectAltName    ::= SEQUENCE OF GeneralName        (extnID 2.5.29.17)
 *   GeneralName dNSName    [2] IA5String
 *   GeneralName iPAddress  [7] OCTET STRING (4 bytes v4 / 16 bytes v6)
 */

/** DER tag numbers used by this parser. */
const TAG_INTEGER = 0x02;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const CLASS_CONTEXT = 0x80;

/** OID 2.5.29.17 subjectAltName. */
const OID_SUBJECT_ALT_NAME = '2.5.29.17';
/** OID 2.5.4.3 commonName. */
const OID_COMMON_NAME = '2.5.4.3';

/** The extracted identity material. */
export interface CertIdentity {
  /** dNSName SANs (lowercased is left to the caller) and iPAddress SANs. */
  subjectAltNames: string[];
  /** subject Common Name, if present. */
  commonName?: string;
}

/** A parsed TLV element and where its content sits in the buffer. */
interface Tlv {
  tag: number;
  /** Offset of the first content byte. */
  start: number;
  /** Offset just past the last content byte. */
  end: number;
  /** Offset just past this whole element (== end for definite length). */
  next: number;
}

/**
 * Read one definite-length DER TLV starting at `pos`. Throws on malformed
 * length encoding or truncation. Indefinite-length (0x80) is rejected, as DER
 * forbids it.
 */
function readTlv(buf: Uint8Array, pos: number): Tlv {
  if (pos + 2 > buf.length) throw new Error('truncated TLV header');
  const tag = buf[pos];
  let i = pos + 1;
  let len = buf[i++];
  if (len === 0x80) throw new Error('indefinite length not allowed in DER');
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error('unsupported length encoding');
    if (i + numBytes > buf.length) throw new Error('truncated length');
    len = 0;
    for (let k = 0; k < numBytes; k++) {
      len = len * 256 + buf[i++];
    }
  }
  const start = i;
  const end = start + len;
  if (end > buf.length) throw new Error('content exceeds buffer');
  return { tag, start, end, next: end };
}

/** Decode a DER OID content region into dotted-decimal string. */
function decodeOid(buf: Uint8Array, start: number, end: number): string {
  if (start >= end) return '';
  const parts: number[] = [];
  const first = buf[start];
  parts.push(Math.floor(first / 40));
  parts.push(first % 40);
  let value = 0;
  for (let i = start + 1; i < end; i++) {
    const b = buf[i];
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Decode an ASCII/UTF-8 string content region. */
function decodeString(buf: Uint8Array, start: number, end: number): string {
  let out = '';
  for (let i = start; i < end; i++) out += String.fromCharCode(buf[i]);
  // The content is IA5String (dNSName) or a directory string (CN). For dNSName
  // and typical CNs this is 7-bit ASCII; treat bytes as Latin-1 code points,
  // which is exact for ASCII and avoids importing a UTF-8 decoder.
  return out;
}

/** Format an iPAddress OCTET STRING (4 or 16 bytes) as a text address. */
function decodeIpAddress(buf: Uint8Array, start: number, end: number): string | null {
  const len = end - start;
  if (len === 4) {
    return `${buf[start]}.${buf[start + 1]}.${buf[start + 2]}.${buf[start + 3]}`;
  }
  if (len === 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((buf[start + i] << 8) | buf[start + i + 1]).toString(16));
    }
    return compressIpv6(groups);
  }
  return null;
}

/** Compress an 8-group IPv6 address to its canonical "::" form. */
function compressIpv6(groups: string[]): string {
  // Find the longest run of "0" groups to replace with "::".
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '0') {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(':');
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/** Iterate the direct child TLVs within [start, end). */
function* children(buf: Uint8Array, start: number, end: number): Generator<Tlv> {
  let pos = start;
  while (pos < end) {
    const tlv = readTlv(buf, pos);
    yield tlv;
    pos = tlv.next;
  }
}

/**
 * Extract SANs given the content of a subjectAltName extnValue OCTET STRING.
 * That content is itself the DER of a SEQUENCE OF GeneralName. `start`/`end`
 * delimit the OCTET STRING content region.
 */
function parseSanExtension(buf: Uint8Array, start: number, end: number, out: string[]): void {
  const seq = readTlv(buf, start);
  if (seq.tag !== TAG_SEQUENCE) return;
  for (const gn of children(buf, seq.start, seq.end)) {
    const tagNum = gn.tag & 0x1f;
    const isContext = (gn.tag & 0xc0) === CLASS_CONTEXT;
    if (!isContext) continue;
    if (tagNum === 2) {
      // dNSName [2] IA5String (primitive)
      out.push(decodeString(buf, gn.start, gn.end));
    } else if (tagNum === 7) {
      // iPAddress [7] OCTET STRING (primitive)
      const ip = decodeIpAddress(buf, gn.start, gn.end);
      if (ip) out.push(ip);
    }
  }
  void end;
}

/**
 * Extract the Common Name from a subject Name (RDNSequence). Returns the last
 * CN encountered (the most specific), or undefined.
 */
function parseCommonName(buf: Uint8Array, subject: Tlv): string | undefined {
  let cn: string | undefined;
  // subject ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeValue)
  for (const rdn of children(buf, subject.start, subject.end)) {
    if (rdn.tag !== TAG_SET) continue;
    for (const atv of children(buf, rdn.start, rdn.end)) {
      if (atv.tag !== TAG_SEQUENCE) continue;
      const it = children(buf, atv.start, atv.end);
      const oidTlv = it.next().value as Tlv | undefined;
      const valTlv = it.next().value as Tlv | undefined;
      if (!oidTlv || !valTlv || oidTlv.tag !== TAG_OID) continue;
      if (decodeOid(buf, oidTlv.start, oidTlv.end) === OID_COMMON_NAME) {
        cn = decodeString(buf, valTlv.start, valTlv.end);
      }
    }
  }
  return cn;
}

/**
 * Parse a DER-encoded X.509 leaf certificate and extract the subjectAltName
 * dNSName/iPAddress entries and the subject Common Name. Returns undefined when
 * the input cannot be parsed as an X.509 certificate at all, so the caller can
 * fail closed. A successful parse with no SANs returns an empty array (a valid
 * outcome the caller must still reject for a named host if no name matches).
 */
export function parseCertIdentity(der: Uint8Array): CertIdentity | undefined {
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sigValue }
    const cert = readTlv(der, 0);
    if (cert.tag !== TAG_SEQUENCE) return undefined;
    const tbs = readTlv(der, cert.start);
    if (tbs.tag !== TAG_SEQUENCE) return undefined;

    // Walk the TBSCertificate fields in order to locate `subject` and
    // `extensions`. Field order (RFC 5280):
    //   [0] version (optional, explicit), serialNumber INTEGER, signature SEQ,
    //   issuer Name (SEQ), validity SEQ, subject Name (SEQ),
    //   subjectPublicKeyInfo SEQ, ... , [3] extensions (optional, explicit).
    const fields: Tlv[] = [...children(der, tbs.start, tbs.end)];
    let idx = 0;
    // Optional explicit [0] version.
    if (fields[idx] && (fields[idx].tag & 0xc0) === CLASS_CONTEXT && (fields[idx].tag & 0x1f) === 0) {
      idx++;
    }
    // serialNumber INTEGER
    if (!fields[idx] || fields[idx].tag !== TAG_INTEGER) return undefined;
    idx++;
    // signature (AlgorithmIdentifier SEQUENCE)
    if (!fields[idx] || fields[idx].tag !== TAG_SEQUENCE) return undefined;
    idx++;
    // issuer (Name SEQUENCE)
    if (!fields[idx] || fields[idx].tag !== TAG_SEQUENCE) return undefined;
    idx++;
    // validity (SEQUENCE)
    if (!fields[idx] || fields[idx].tag !== TAG_SEQUENCE) return undefined;
    idx++;
    // subject (Name SEQUENCE)
    const subject = fields[idx];
    if (!subject || subject.tag !== TAG_SEQUENCE) return undefined;
    idx++;

    const commonName = parseCommonName(der, subject);

    // Find the extensions container: an explicit [3] wrapping a SEQUENCE OF
    // Extension. It is the last field when present.
    const subjectAltNames: string[] = [];
    for (let j = idx; j < fields.length; j++) {
      const f = fields[j];
      if ((f.tag & 0xc0) === CLASS_CONTEXT && (f.tag & 0x1f) === 3) {
        const extsSeq = readTlv(der, f.start);
        if (extsSeq.tag !== TAG_SEQUENCE) break;
        for (const ext of children(der, extsSeq.start, extsSeq.end)) {
          if (ext.tag !== TAG_SEQUENCE) continue;
          const it = children(der, ext.start, ext.end);
          const oidTlv = it.next().value as Tlv | undefined;
          if (!oidTlv || oidTlv.tag !== TAG_OID) continue;
          if (decodeOid(der, oidTlv.start, oidTlv.end) !== OID_SUBJECT_ALT_NAME) continue;
          // Skip an optional critical BOOLEAN; the extnValue is the last field.
          let last: Tlv | undefined;
          for (const child of it) last = child;
          if (last) parseSanExtension(der, last.start, last.end, subjectAltNames);
        }
        break;
      }
    }

    return { subjectAltNames, commonName };
  } catch {
    return undefined;
  }
}
