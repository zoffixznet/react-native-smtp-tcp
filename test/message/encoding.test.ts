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

  it('T-RFC2047-IDEMPOTENT: pure-ASCII passes through, encoded not double-encoded', () => {
    expect(encodeHeaderWord('Plain ASCII subject')).toBe('Plain ASCII subject');
    const already = '=?UTF-8?B?Y2Fmw6k=?=';
    expect(encodeHeaderWord(already)).toBe(already);
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
