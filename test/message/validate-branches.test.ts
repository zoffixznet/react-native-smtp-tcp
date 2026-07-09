import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import {
  assertNoDangerousControls,
  validateClientId,
  validateDomainSyntax,
  isAscii,
} from '../../src/message/validate';
import { isIPv6 } from '../../src/net-util';
import { base64DecodeStrict, encodeHeaderWord, foldHeaderLine } from '../../src/message/encoding';
import { SmtpMessageError } from '../../src/protocol/errors';

describe('validate branches', () => {
  it('assertNoDangerousControls rejects C0 controls but allows TAB', () => {
    expect(() => assertNoDangerousControls('a\x01b', 'x')).toThrow(SmtpMessageError);
    expect(() => assertNoDangerousControls('a\x7fb', 'x')).toThrow(SmtpMessageError);
    expect(() => assertNoDangerousControls('a\tb', 'x')).not.toThrow();
  });

  it('validateClientId accepts a domain and an address literal, rejects junk', () => {
    expect(() => validateClientId('mail.example.com')).not.toThrow();
    expect(() => validateClientId('[192.0.2.1]')).not.toThrow();
    expect(() => validateClientId('')).toThrow();
    expect(() => validateClientId('bad host')).toThrow();
    expect(() => validateClientId('a'.repeat(300))).toThrow();
  });

  it('validateDomainSyntax rejects a malformed address literal', () => {
    expect(() => validateDomainSyntax('[not*valid]', 'x')).toThrow();
    expect(() => validateDomainSyntax('[192.0.2.1]', 'x')).not.toThrow();
  });

  it('isAscii distinguishes ASCII from non-ASCII', () => {
    expect(isAscii('plain')).toBe(true);
    expect(isAscii('café')).toBe(false);
  });
});

describe('IPv6 edge cases', () => {
  it('handles compression and length bounds', () => {
    expect(isIPv6('fe80::1')).toBe(true);
    expect(isIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true);
    expect(isIPv6('12345::1')).toBe(false); // group too long
    expect(isIPv6('1:2:3:4:5:6:7:8:9')).toBe(false); // too many groups
    expect(isIPv6('nocolon')).toBe(false);
  });
});

describe('encoding branches', () => {
  it('base64DecodeStrict accepts valid padding at the end', () => {
    expect(base64DecodeStrict('YQ==').toString()).toBe('a');
    expect(base64DecodeStrict('YWI=').toString()).toBe('ab');
  });

  it('encodeHeaderWord re-encodes encoded-word-shaped ASCII (no verbatim pass-through)', () => {
    // Literal text that merely resembles an encoded-word must be encoded, not
    // emitted verbatim, or a receiver would decode it into different characters.
    const enc = '=?UTF-8?Q?caf=C3=A9?=';
    const out = encodeHeaderWord(enc);
    expect(out).not.toBe(enc);
    // The output no longer contains a bare, decodable token equal to the input.
    expect(out).toMatch(/^=\?UTF-8\?B\?/);
    // Round-trips back to the exact literal characters the user supplied.
    const m = /=\?UTF-8\?B\?([^?]*)\?=/.exec(out);
    expect(m).not.toBeNull();
    expect(Buffer.from(m![1], 'base64').toString('utf8')).toBe(enc);
  });

  it('foldHeaderLine keeps a value with a single short token intact', () => {
    expect(foldHeaderLine('X', 'value')).toBe('X: value');
  });
});
