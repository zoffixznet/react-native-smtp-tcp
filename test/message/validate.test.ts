import { describe, it, expect } from 'vitest';
import {
  assertNoControlChars,
  assertValidHeaderName,
  validateAddress,
  splitAddress,
  LIMITS,
} from '../../src/message/validate';
import { SmtpMessageError } from '../../src/protocol/errors';

describe('control-character gate (SEC-14)', () => {
  it('rejects bare CR, bare LF, and NUL independently', () => {
    expect(() => assertNoControlChars('a\rb', 'x')).toThrow(SmtpMessageError);
    expect(() => assertNoControlChars('a\nb', 'x')).toThrow(SmtpMessageError);
    expect(() => assertNoControlChars('a\x00b', 'x')).toThrow(SmtpMessageError);
    // CRLF pair is also rejected (contains both CR and LF).
    expect(() => assertNoControlChars('a\r\nb', 'x')).toThrow(SmtpMessageError);
    // Clean input passes.
    expect(() => assertNoControlChars('clean value', 'x')).not.toThrow();
  });
});

describe('address validation', () => {
  it('T-ENVELOPE-CRLF: rejects CRLF-injected envelope addresses', () => {
    expect(() =>
      validateAddress('legit@example.com\r\nRCPT TO:<attacker@evil.com>', 'rcpt'),
    ).toThrow(SmtpMessageError);
    expect(() =>
      validateAddress('a@b.com\r\nMAIL FROM:<ceo@trusted.com>', 'mail'),
    ).toThrow(SmtpMessageError);
  });

  it('T-BARE-CR-LF-ADDR: rejects bare LF and bare CR in addresses', () => {
    expect(() => validateAddress('user@example.com\nRCPT TO:<x@y>', 'rcpt')).toThrow();
    expect(() => validateAddress('user@example.com\rDATA', 'rcpt')).toThrow();
  });

  it('T-NUL-ADDR: rejects NUL and trailing NUL in addresses', () => {
    expect(() => validateAddress('user@exa\x00mple.com', 'rcpt')).toThrow();
    expect(() => validateAddress('user@example.com\x00', 'rcpt')).toThrow();
  });

  it('T-SIZE-LIMITS: enforces RFC 5321 local-part/path limits', () => {
    const longLocal = 'a'.repeat(65) + '@example.com';
    expect(() => validateAddress(longLocal, 'x')).toThrow(/local part/);
    const longPath = 'a'.repeat(300) + '@example.com';
    expect(() => validateAddress(longPath, 'x')).toThrow();
    // Over the 254 hard cap.
    const tooLong = 'a'.repeat(250) + '@' + 'b'.repeat(20) + '.com';
    expect(() => validateAddress(tooLong, 'x')).toThrow();
  });

  it('accepts a valid address and splits it', () => {
    const s = validateAddress('me@example.com', 'x');
    expect(s.localPart).toBe('me');
    expect(s.domain).toBe('example.com');
    expect(LIMITS.maxRecipients).toBe(100);
  });

  it('T-QUOTED-LOCALPART: parses a quoted local part with specials', () => {
    const s = splitAddress('"attacker -Param"@example.com');
    expect(s.quotedLocal).toBe(true);
    expect(s.domain).toBe('example.com');
    // Control chars inside the quoted string are still rejected by the gate.
    expect(() => validateAddress('"a\rb"@example.com', 'x')).toThrow();
  });

  it('rejects addresses with an unexpected structure', () => {
    expect(() => validateAddress('no-at-sign', 'x')).toThrow();
    expect(() => validateAddress('@example.com', 'x')).toThrow();
    expect(() => validateAddress('me@', 'x')).toThrow();
    expect(() => validateAddress('me@bad_domain!', 'x')).toThrow();
    expect(() => validateAddress('me@a..b.com', 'x')).toThrow();
  });

  it('accepts an address literal domain', () => {
    expect(() => validateAddress('me@[192.0.2.1]', 'x')).not.toThrow();
    expect(() => validateAddress('me@[IPv6:2001:db8::1]', 'x')).not.toThrow();
  });

  it('requireAscii rejects a non-ASCII local part', () => {
    expect(() => validateAddress('mé@example.com', 'x', { requireAscii: true })).toThrow();
    expect(() => validateAddress('mé@example.com', 'x', { requireAscii: false })).not.toThrow();
  });
});

describe('header name validation', () => {
  it('T-MALFORMED-HEADER-NAME: rejects colon, space, and control chars', () => {
    expect(() => assertValidHeaderName('X-Bad: Injected')).toThrow();
    expect(() => assertValidHeaderName('X Bad')).toThrow();
    expect(() => assertValidHeaderName('X\r\nBad')).toThrow();
    expect(() => assertValidHeaderName('')).toThrow();
    expect(() => assertValidHeaderName('X-Good')).not.toThrow();
  });
});
