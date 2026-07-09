/**
 * Content and header encoding: base64, quoted-printable, RFC 2047 encoded-words,
 * and header folding. All output uses CRLF line endings and stays within the
 * RFC line-length limits.
 */

import { Buffer } from 'buffer';
import { SmtpMessageError } from '../protocol/errors';
import { isAscii } from './validate';

const CRLF = '\r\n';

/** Encode bytes as base64 wrapped at 76 characters per line (RFC 2045). */
export function base64Wrapped(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  const b64 = buf.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) {
    lines.push(b64.slice(i, i + 76));
  }
  return lines.join(CRLF);
}

/** Single-line base64 with no wrapping (used for AUTH payloads). */
export function base64(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64');
}

const B64_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Strictly decode a base64 challenge. Rejects any character outside the base64
 * alphabet and rejects '=' padding anywhere but at the very end. Used for SASL
 * 334 challenges so a hostile server cannot smuggle bytes through a lax decoder.
 */
export function base64DecodeStrict(input: string): Buffer {
  if (!B64_ALPHABET.test(input)) {
    throw new SmtpMessageError('challenge contains non-base64 characters');
  }
  const firstPad = input.indexOf('=');
  if (firstPad !== -1) {
    // Every character from the first '=' to the end must also be '='.
    for (let i = firstPad; i < input.length; i++) {
      if (input[i] !== '=') {
        throw new SmtpMessageError('challenge has misplaced base64 padding');
      }
    }
  }
  if (input.length % 4 !== 0) {
    throw new SmtpMessageError('challenge has an invalid base64 length');
  }
  return Buffer.from(input, 'base64');
}

const QP_SAFE = (code: number): boolean =>
  // Printable ASCII except '=' (0x3D). Space and tab handled separately.
  (code >= 0x20 && code <= 0x7e && code !== 0x3d);

/**
 * Quoted-printable encode a body, wrapping at 76 characters with '=' soft line
 * breaks (RFC 2045 sec 6.7). Input is treated as UTF-8. Line endings in the
 * source must already be normalized to CRLF; hard line breaks are preserved.
 */
export function quotedPrintable(input: string): string {
  const bytes = Buffer.from(input, 'utf8');
  const out: string[] = [];
  let line = '';

  const pushSoftBreak = () => {
    out.push(line + '=');
    line = '';
  };

  for (let i = 0; i < bytes.length; i++) {
    const code = bytes[i];
    // Preserve existing CRLF hard breaks.
    if (code === 0x0d && bytes[i + 1] === 0x0a) {
      // Trailing whitespace before a hard break must be encoded.
      out.push(line);
      line = '';
      i++; // skip the LF
      continue;
    }

    let token: string;
    if (code === 0x20 || code === 0x09) {
      // Space/tab: literal unless at end of line (handled at line flush).
      token = String.fromCharCode(code);
    } else if (QP_SAFE(code)) {
      token = String.fromCharCode(code);
    } else {
      token = '=' + code.toString(16).toUpperCase().padStart(2, '0');
    }

    // Wrap at 76 columns, leaving room for the trailing '='.
    if (line.length + token.length > 75) {
      pushSoftBreak();
    }
    line += token;
  }
  out.push(line);

  // Encode any trailing space/tab at line ends so they survive transport.
  return out
    .map((l) => l.replace(/([ \t])$/, (m) => '=' + m.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')))
    .join(CRLF);
}

/**
 * True when a pure-ASCII value contains a substring shaped like an RFC 2047
 * encoded-word token (=?charset?enc?text?=). Such text MUST be encoded rather
 * than emitted verbatim: a receiving MUA parses and decodes encoded-words
 * wherever they appear syntactically, so passing the literal characters through
 * would silently substitute different characters on the recipient's display.
 */
function looksLikeEncodedWord(value: string): boolean {
  return /=\?[^?]*\?[^?]*\?[^?]*\?=/.test(value);
}

/**
 * RFC 2047 encoded-word for a header value. Chooses B encoding, keeps each
 * encoded-word within 75 characters total, and splits long input into multiple
 * encoded-words joined by CRLF + a single space. Plain pure-ASCII input passes
 * through unchanged; ASCII that resembles an encoded-word is encoded so the
 * recipient renders the literal characters supplied (no spoofing via a token
 * that merely looks pre-encoded). Encoding is decided purely from the raw input,
 * so it is safe even for library-produced output.
 */
export function encodeHeaderWord(value: string): string {
  // Pure ASCII with no CR/LF and no encoded-word-shaped token is safe verbatim.
  // A content-inspecting "already encoded" guard cannot distinguish library
  // output from user text that merely resembles it, so any encoded-word-shaped
  // ASCII is encoded (its '=' and '?' become part of the base64 payload) rather
  // than passed through. That closes the RFC 2047 spoofing vector.
  if (isAscii(value) && !/[\r\n]/.test(value) && !looksLikeEncodedWord(value)) {
    return value;
  }

  const charset = 'UTF-8';
  // Use base64 for the encoded content; simple to bound per encoded-word.
  const bytes = Buffer.from(value, 'utf8');
  // Each encoded-word is: =?UTF-8?B?<data>?= and must be <= 75 chars total.
  // Overhead = "=?UTF-8?B?" (10) + "?=" (2) = 12. So data budget = 63 chars of
  // base64, which must be a multiple of 4: use 60 base64 chars => 45 raw bytes.
  const prefix = `=?${charset}?B?`;
  const suffix = '?=';
  const rawBytesPerWord = 45;

  const words: string[] = [];
  let i = 0;
  while (i < bytes.length) {
    // Never cut in the middle of a multi-byte UTF-8 character: each encoded-word
    // must encode an integral number of characters (RFC 2047 sec 2). Back the
    // end off while it lands on a UTF-8 continuation byte (0x80-0xBF).
    let end = Math.min(i + rawBytesPerWord, bytes.length);
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) {
      end--;
    }
    const chunk = bytes.subarray(i, end);
    words.push(prefix + chunk.toString('base64') + suffix);
    i = end;
  }
  if (words.length === 0) {
    words.push(prefix + suffix);
  }
  // Join encoded-words with CRLF + space so each header line stays short.
  return words.join(CRLF + ' ');
}

/**
 * Fold a header line ("Name: value") at legal points so no line exceeds 998
 * octets, preferring to keep lines under 78. Folding inserts CRLF followed by a
 * single space; unfolding (removing CRLF before WSP) restores the exact value.
 *
 * The value must not contain CR or LF except the CRLF+WSP introduced here.
 */
export function foldHeaderLine(name: string, value: string): string {
  const full = `${name}: ${value}`;
  // If the value already contains folds (from encoded-word joining), respect
  // them: fold each physical line independently.
  const physicalLines = full.split(CRLF);
  const folded: string[] = [];
  for (const phys of physicalLines) {
    folded.push(foldSinglePhysicalLine(phys));
  }
  return folded.join(CRLF);
}

function foldSinglePhysicalLine(line: string): string {
  if (Buffer.byteLength(line, 'utf8') <= 78) {
    return line;
  }
  const out: string[] = [];
  let current = '';
  const tokens = line.split(' ');
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const candidate = current.length === 0 ? token : current + ' ' + token;
    if (Buffer.byteLength(candidate, 'utf8') > 78 && current.length > 0) {
      out.push(current);
      // Continuation lines begin with a single space (the fold WSP).
      current = ' ' + token;
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) out.push(current);

  // Guard against a single token exceeding 998 octets, which cannot be folded.
  const rejoined = out.join(CRLF);
  for (const physical of rejoined.split(CRLF)) {
    if (Buffer.byteLength(physical, 'utf8') > 998) {
      throw new SmtpMessageError(
        'header value contains an unfoldable run longer than 998 octets',
      );
    }
  }
  return rejoined;
}
