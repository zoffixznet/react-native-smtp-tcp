import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import {
  base64Wrapped,
  quotedPrintable,
  encodeHeaderWord,
  foldHeaderLine,
} from '../../src/message/encoding';

const CRLF = '\r\n';

describe('base64 wrapping', () => {
  it('wraps at 76 chars per line', () => {
    const out = base64Wrapped(Buffer.alloc(200, 0x41));
    for (const line of out.split(CRLF)) {
      expect(line.length).toBeLessThanOrEqual(76);
    }
    // Round-trips.
    expect(Buffer.from(out.replace(/\r\n/g, ''), 'base64').equals(Buffer.alloc(200, 0x41))).toBe(true);
  });
});

describe('quoted-printable', () => {
  it('encodes non-ASCII as =XX and wraps at 76 with soft breaks', () => {
    const out = quotedPrintable('café ' + 'x'.repeat(200));
    for (const line of out.split(CRLF)) {
      expect(line.length).toBeLessThanOrEqual(76);
    }
    expect(out).toContain('caf=C3=A9');
  });

  it('preserves CRLF hard breaks', () => {
    const out = quotedPrintable('line1\r\nline2');
    expect(out).toBe('line1\r\nline2');
  });
});

/**
 * Decode an RFC 2047 base64 encoded-word run the way a conformant receiver does:
 * decode each =?UTF-8?B?...?= word independently and concatenate the results.
 * Any linear whitespace between adjacent encoded-words is dropped (RFC 2047
 * sec 6.2), which matches the CRLF+space join this library emits.
 */
function decodeEncodedWords(out: string): string {
  const tokenRe = /=\?UTF-8\?B\?([^?]*)\?=/g;
  const parts: Buffer[] = [];
  let m: RegExpExecArray | null;
  let sawToken = false;
  while ((m = tokenRe.exec(out)) !== null) {
    sawToken = true;
    parts.push(Buffer.from(m[1], 'base64'));
  }
  // If it was not encoded at all, return the raw string.
  if (!sawToken) return out;
  return Buffer.concat(parts).toString('utf8');
}

describe('RFC 2047 encoded-words', () => {
  it('T-RFC2047-SUBJECT: encodes accents, each word <=75 chars', () => {
    const out = encodeHeaderWord('Rappel: réunion café ' + 'é'.repeat(100));
    for (const word of out.split(CRLF + ' ')) {
      expect(word.length).toBeLessThanOrEqual(75);
      expect(word).toMatch(/^=\?UTF-8\?B\?.*\?=$/);
      // No SPACE/HTAB/CR/LF inside an encoded-word.
      expect(word.slice(2, -2)).not.toMatch(/[ \t\r\n]/);
    }
  });

  it('T-RFC2047-MULTIBYTE: never splits a multi-byte UTF-8 char across words', () => {
    // 2-byte accented Latin: 23 * 2 = 46 bytes, so the naive 45-byte cut would
    // split the 23rd character across the word boundary and yield U+FFFD.
    for (const value of ['á'.repeat(23), 'é'.repeat(50), 'ñü'.repeat(40)]) {
      const out = encodeHeaderWord(value);
      const decoded = decodeEncodedWords(out);
      expect(decoded).toBe(value);
      expect(decoded).not.toContain('�');
    }
    // 4-byte emoji crossing the boundary too.
    for (const value of ['😀'.repeat(12), '👍🏽'.repeat(8)]) {
      const out = encodeHeaderWord(value);
      const decoded = decodeEncodedWords(out);
      expect(decoded).toBe(value);
      expect(decoded).not.toContain('�');
    }
  });

  it('T-RFC2047-PLAIN-ASCII: plain pure-ASCII passes through unchanged', () => {
    expect(encodeHeaderWord('Plain ASCII subject')).toBe('Plain ASCII subject');
  });

  it('T-RFC2047-NO-SPOOF: encoded-word-shaped ASCII is re-encoded, not passed through', () => {
    // A subject/name the user literally typed that resembles an encoded-word
    // must NOT be emitted verbatim; a receiver would otherwise decode it into
    // different characters. After encoding, the literal characters must be what
    // a conformant decoder recovers (round-trip equals the original text).
    const spoofs = [
      'Re: =?UTF-8?B?8J+YgA==?= your invoice', // token decodes to an emoji
      'Support =?UTF-8?Q?=41=64=6D=69=6E?=',   // Q token decodes to "Admin"
      '=?UTF-8?B?Y2Fmw6k=?=',                   // token decodes to "café"
    ];
    for (const value of spoofs) {
      const out = encodeHeaderWord(value);
      // The output must be encoded (it now carries our own encoded-word wrapper)
      // and must decode back to the exact literal characters the user supplied.
      expect(out).not.toBe(value);
      expect(decodeEncodedWords(out)).toBe(value);
    }
  });

  it('T-RFC2047-NO-SMUGGLE: a display name with CR/LF yields no literal CR/LF', () => {
    const out = encodeHeaderWord('A\r\nB');
    expect(out).not.toMatch(/(?<!=\?[^?]*\?[BQ]\?[^?]*)[\r\n]/);
    // The encoded-word data decodes back to the original.
    const m = /=\?UTF-8\?B\?([^?]*)\?=/.exec(out);
    expect(m).not.toBeNull();
    expect(Buffer.from(m![1], 'base64').toString('utf8')).toBe('A\r\nB');
  });
});

describe('header folding', () => {
  it('T-LINE-FOLD-998: folds a long header value under 998 octets and unfolds', () => {
    const value = Array.from({ length: 400 }, (_, i) => `token${i}`).join(' ');
    const folded = foldHeaderLine('X-Long', value);
    for (const line of folded.split(CRLF)) {
      expect(Buffer.byteLength(line, 'utf8')).toBeLessThanOrEqual(998);
    }
    // Unfolding (remove CRLF before WSP) restores the exact "Name: value".
    const unfolded = folded.replace(/\r\n /g, ' ');
    expect(unfolded).toBe(`X-Long: ${value}`);
  });

  it('rejects a single unfoldable token longer than 998 octets', () => {
    const value = 'x'.repeat(1500);
    expect(() => foldHeaderLine('X-Big', value)).toThrow();
  });

  it('leaves a short header line unfolded', () => {
    expect(foldHeaderLine('Subject', 'short')).toBe('Subject: short');
  });
});
