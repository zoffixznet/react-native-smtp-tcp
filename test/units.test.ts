import { describe, it, expect } from 'vitest';
import { isIP, isIPv4, isIPv6 } from '../src/net-util';
import { certFingerprintMatches, normalizeFingerprint } from '../src/protocol/pinning';
import { redactCommand, redactAuthReply } from '../src/protocol/redact';

describe('IP recognition', () => {
  it('recognizes IPv4', () => {
    expect(isIPv4('127.0.0.1')).toBe(true);
    expect(isIPv4('255.255.255.255')).toBe(true);
    expect(isIPv4('256.0.0.1')).toBe(false);
    expect(isIPv4('01.2.3.4')).toBe(false);
    expect(isIPv4('1.2.3')).toBe(false);
  });
  it('recognizes IPv6', () => {
    expect(isIPv6('2001:db8::1')).toBe(true);
    expect(isIPv6('::1')).toBe(true);
    expect(isIPv6('not:an:ip:g')).toBe(false);
    expect(isIPv6('1::2::3')).toBe(false);
    expect(isIP('example.com')).toBe(false);
  });
});

describe('certificate-fingerprint pinning', () => {
  it('normalizes colon-separated and plain hex', () => {
    expect(normalizeFingerprint('AA:BB:CC')).toBe('aabbcc');
    expect(normalizeFingerprint('aabbcc')).toBe('aabbcc');
    expect(normalizeFingerprint('')).toBeNull();
    expect(normalizeFingerprint(undefined)).toBeNull();
    expect(normalizeFingerprint('::::')).toBeNull();
  });

  it('matches a fingerprint pin regardless of separators or case', () => {
    const cert = { fingerprint256: 'AB:CD:EF:12:34:56' };
    expect(certFingerprintMatches(cert, 'ab:cd:ef:12:34:56')).toBe(true);
    expect(certFingerprintMatches(cert, 'abcdef123456')).toBe(true);
    expect(certFingerprintMatches(cert, 'ABCDEF123456')).toBe(true);
  });

  it('rejects a mismatching or missing fingerprint', () => {
    expect(certFingerprintMatches({ fingerprint256: 'AB:CD' }, 'ff:ee')).toBe(false);
    // Different length.
    expect(certFingerprintMatches({ fingerprint256: 'ABCD' }, 'ABCDEF')).toBe(false);
    // No certificate / no fingerprint field.
    expect(certFingerprintMatches(undefined, 'abcd')).toBe(false);
    expect(certFingerprintMatches({}, 'abcd')).toBe(false);
    // Empty configured pin never matches.
    expect(certFingerprintMatches({ fingerprint256: 'abcd' }, '')).toBe(false);
  });
});

describe('redaction', () => {
  it('redacts AUTH command arguments but keeps the verb and mechanism', () => {
    expect(redactCommand('AUTH PLAIN AGZvbwBiYXI=')).toBe('AUTH PLAIN ***');
    expect(redactCommand('AUTH LOGIN')).toBe('AUTH LOGIN');
    expect(redactCommand('EHLO host')).toBe('EHLO host');
    expect(redactCommand('MAIL FROM:<a@b.com>\r\n')).toBe('MAIL FROM:<a@b.com>');
  });

  it('redacts the text of an AUTH reply while keeping the code', () => {
    expect(redactAuthReply('334 VXNlcm5hbWU6')).toBe('334 ***');
    expect(redactAuthReply('garbage')).toBe('***');
  });
});
