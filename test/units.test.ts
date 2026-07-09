import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { matchHostname, verifyHostname } from '../src/hostname';
import { isIP, isIPv4, isIPv6 } from '../src/net-util';
import { computeSpkiSha256, pinMatches } from '../src/protocol/pinning';
import { redactCommand, redactAuthReply } from '../src/protocol/redact';
import { createHash } from 'crypto';

const sha256 = (d: Uint8Array) => new Uint8Array(createHash('sha256').update(d).digest());

describe('hostname matching', () => {
  it('matches exact and wildcard SANs, not across dot boundaries', () => {
    expect(matchHostname('mail.example.com', 'mail.example.com')).toBe(true);
    expect(matchHostname('mail.example.com', '*.example.com')).toBe(true);
    expect(matchHostname('a.b.example.com', '*.example.com')).toBe(false);
    expect(matchHostname('example.com', '*.example.com')).toBe(false);
    expect(matchHostname('mail.example.com', 'MAIL.EXAMPLE.COM')).toBe(true);
  });

  it('verifyHostname prefers SAN and uses CN only as a fallback', () => {
    expect(verifyHostname('mail.example.com', ['mail.example.com'])).toBe(true);
    expect(verifyHostname('mail.example.com', ['other.example.com'])).toBe(false);
    // CN fallback only when no dNSName SANs.
    expect(verifyHostname('mail.example.com', [], 'mail.example.com')).toBe(true);
    expect(verifyHostname('mail.example.com', ['other.example.com'], 'mail.example.com')).toBe(false);
  });

  it('matches an IP host only against an exact IP SAN', () => {
    expect(verifyHostname('192.0.2.1', ['192.0.2.1'])).toBe(true);
    expect(verifyHostname('192.0.2.1', ['192.0.2.2'])).toBe(false);
    expect(verifyHostname('192.0.2.1', ['*.example.com'])).toBe(false);
  });

  it('rejects public-suffix / TLD-position wildcards (SEC-6/SEC-7/SEC-11)', () => {
    // A wildcard sitting in a public-suffix / effective-TLD position must never
    // validate an arbitrary host: "*.com" must not match every ".com" name, and
    // "*.co.uk" must not match every ".co.uk" name. RFC 6125 sec 7.2.
    expect(matchHostname('anything.com', '*.com')).toBe(false);
    expect(matchHostname('victim.co.uk', '*.co.uk')).toBe(false);
    expect(matchHostname('a.com.au', '*.com.au')).toBe(false);
    expect(verifyHostname('anything.com', ['*.com'])).toBe(false);
    expect(verifyHostname('victim.co.uk', ['*.co.uk'])).toBe(false);
    // The legitimate registrable-domain wildcard still works.
    expect(matchHostname('mail.example.co.uk', '*.example.co.uk')).toBe(true);
    expect(matchHostname('mail.example.com', '*.example.com')).toBe(true);
  });

  it('rejects wildcards that are not a single leftmost label', () => {
    // Embedded or trailing "*" is not a legal single-leftmost-label wildcard.
    expect(matchHostname('mail.example.com', 'm*.example.com')).toBe(false);
    expect(matchHostname('mail.example.com', '*mail.example.com')).toBe(false);
    expect(matchHostname('a.b.example.com', '*.*.example.com')).toBe(false);
    expect(matchHostname('mail.example.com', 'mail.*.com')).toBe(false);
  });
});

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

describe('SPKI pinning', () => {
  it('computes and compares an SPKI hash', () => {
    const pubkey = new Uint8Array([1, 2, 3, 4, 5]);
    const hash = computeSpkiSha256({ pubkey }, sha256)!;
    const expected = Buffer.from(sha256(pubkey)).toString('base64');
    expect(hash).toBe(expected);
    expect(pinMatches(hash, expected)).toBe(true);
    expect(pinMatches(hash, Buffer.from(sha256(new Uint8Array([9]))).toString('base64'))).toBe(false);
  });

  it('returns null when no public key is available and never matches', () => {
    expect(computeSpkiSha256(undefined, sha256)).toBeNull();
    expect(computeSpkiSha256({}, sha256)).toBeNull();
    expect(pinMatches(null, 'anything')).toBe(false);
    expect(pinMatches('AAAA', '')).toBe(false);
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
