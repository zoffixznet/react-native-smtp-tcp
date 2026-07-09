/**
 * SASL mechanism encoding for SMTP AUTH: PLAIN, LOGIN, and XOAUTH2.
 *
 * The encoders produce the exact bytes required by the RFCs. Credentials are
 * never logged; the client redacts AUTH command arguments and every line of an
 * AUTH exchange to "***" before anything reaches a logger.
 */

import { Buffer } from 'buffer';
import { SmtpMessageError } from './errors';
import { base64 } from '../message/encoding';

/** Mechanisms this library can perform, in strongest-first preference order. */
export const SUPPORTED_MECHANISMS = ['XOAUTH2', 'LOGIN', 'PLAIN'] as const;

/**
 * The full preference ranking used when selecting from the server's advertised
 * set. Mechanisms the library cannot perform (SCRAM, CRAM-MD5, OAUTHBEARER) are
 * ranked but only chosen if implemented; otherwise the client refuses rather
 * than downgrading silently. CRAM-MD5 is deliberately never preferred.
 */
export const PREFERENCE_ORDER = [
  'XOAUTH2',
  'OAUTHBEARER',
  'SCRAM-SHA-256',
  'LOGIN',
  'PLAIN',
  'CRAM-MD5',
] as const;

/**
 * Select the strongest mechanism that is both advertised by the server and
 * implementable by this library. Returns null if none are acceptable.
 */
export function selectMechanism(
  advertised: string[],
  wantOAuth2: boolean,
): 'XOAUTH2' | 'LOGIN' | 'PLAIN' | null {
  const set = new Set(advertised.map((m) => m.toUpperCase()));
  if (wantOAuth2) {
    return set.has('XOAUTH2') ? 'XOAUTH2' : null;
  }
  // Password auth: prefer PLAIN (single round-trip), then LOGIN. Both are
  // equivalent over TLS. Only advertised mechanisms are ever attempted.
  if (set.has('PLAIN')) return 'PLAIN';
  if (set.has('LOGIN')) return 'LOGIN';
  return null;
}

/** Reject a credential field containing NUL (forbidden in SASL PLAIN). */
function assertNoNul(value: string, field: string): void {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) === 0x00) {
      throw new SmtpMessageError(`${field} contains a NUL byte, which is not allowed`);
    }
  }
}

/** Reject a credential/token field containing CR or LF (command injection). */
function assertNoCrlf(value: string, field: string): void {
  if (value.indexOf('\r') !== -1 || value.indexOf('\n') !== -1) {
    throw new SmtpMessageError(`${field} contains a line break, which is not allowed`);
  }
}

/**
 * AUTH PLAIN initial response: base64(authzid + NUL + authcid + NUL + passwd),
 * UTF-8, single line, no wrapping. authzid is empty (leading NUL).
 */
export function encodePlain(user: string, pass: string): string {
  assertNoNul(user, 'username');
  assertNoNul(pass, 'password');
  const payload = Buffer.concat([
    // authzid is empty; the exchange begins with the separating NUL.
    Buffer.from([0x00]),
    Buffer.from(user, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(pass, 'utf8'),
  ]);
  return base64(payload);
}

/** AUTH LOGIN username response: base64(username). */
export function encodeLoginUser(user: string): string {
  assertNoNul(user, 'username');
  return base64(Buffer.from(user, 'utf8'));
}

/** AUTH LOGIN password response: base64(password). */
export function encodeLoginPass(pass: string): string {
  assertNoNul(pass, 'password');
  return base64(Buffer.from(pass, 'utf8'));
}

/**
 * XOAUTH2 initial response, exactly:
 * base64('user=' + email + 0x01 + 'auth=Bearer ' + token + 0x01 + 0x01)
 */
export function encodeXOAuth2(user: string, accessToken: string): string {
  assertNoNul(user, 'username');
  assertNoNul(accessToken, 'access token');
  assertNoCrlf(user, 'username');
  assertNoCrlf(accessToken, 'access token');
  const payload = Buffer.concat([
    Buffer.from('user=', 'utf8'),
    Buffer.from(user, 'utf8'),
    Buffer.from([0x01]),
    Buffer.from('auth=Bearer ', 'utf8'),
    Buffer.from(accessToken, 'utf8'),
    Buffer.from([0x01, 0x01]),
  ]);
  return base64(payload);
}
