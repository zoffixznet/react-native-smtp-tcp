/**
 * Address normalization and angle-bracket handling for envelope paths.
 */

import { SmtpMessageError } from '../protocol/errors';
import { assertNoControlChars } from './validate';

/** A parsed email address with an optional display name. */
export interface Address {
  /** Optional display name (may contain non-ASCII; encoded per RFC 2047). */
  name?: string;
  /** The addr-spec (local@domain), no angle brackets. */
  address: string;
}

/**
 * Accept a string ("me@example.com") or a structured object and return a
 * normalized {@link Address}. Never re-parses a display name as an address.
 */
export function normalizeAddress(input: string | Address, fieldName: string): Address {
  if (typeof input === 'string') {
    return { address: stripBrackets(input.trim(), fieldName) };
  }
  if (input === null || typeof input !== 'object' || typeof input.address !== 'string') {
    throw new SmtpMessageError(`${fieldName} must be a string or an { address } object`);
  }
  const address = stripBrackets(input.address.trim(), fieldName);
  const out: Address = { address };
  if (input.name !== undefined) {
    if (typeof input.name !== 'string') {
      throw new SmtpMessageError(`${fieldName} display name must be a string`);
    }
    out.name = input.name;
  }
  return out;
}

/**
 * Remove a single surrounding pair of angle brackets if present, so an already
 * bracketed address is not double-wrapped later. Rejects control characters
 * first (fail closed).
 */
export function stripBrackets(address: string, fieldName: string): string {
  assertNoControlChars(address, fieldName);
  let result = address;
  if (result.startsWith('<') && result.endsWith('>')) {
    result = result.slice(1, -1).trim();
  }
  // A remaining bracket indicates a malformed/injected address.
  if (result.includes('<') || result.includes('>')) {
    throw new SmtpMessageError(`${fieldName} contains an unexpected angle bracket`);
  }
  return result;
}

/** Wrap an addr-spec in angle brackets for use in MAIL FROM / RCPT TO. */
export function angleWrap(address: string): string {
  return `<${address}>`;
}
