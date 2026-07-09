/**
 * Input validation at the serialization boundary.
 *
 * The control-character gate here is the primary, unconditional injection
 * defense. Every user-controlled field that flows into an SMTP command or an
 * RFC 5322 header passes through {@link assertNoControlChars} before it is
 * serialized. Bare CR, bare LF, and NUL are each rejected independently, not
 * only as a CRLF pair. Address grammar parsing exists for correctness but is
 * never the sole security check.
 */

import { SmtpMessageError } from '../protocol/errors';

/** RFC 5321 size limits (octets). */
export const LIMITS = {
  localPart: 64,
  domain: 255,
  path: 256,
  commandLine: 512,
  textLine: 998,
  maxRecipients: 100,
  /** RFC 5321 caps a whole email address (path without brackets) well under
   * this; 254 is the widely used practical maximum used as a hard input cap. */
  emailAddress: 254,
} as const;

const CR = 0x0d;
const LF = 0x0a;
const NUL = 0x00;

/**
 * Reject bare CR, bare LF, and NUL in a user-controlled field. This is the
 * unconditional gate against SMTP command and header injection. It fails closed
 * by throwing; callers must never strip and continue.
 *
 * @param value the field value to check
 * @param fieldName a non-secret label used only in the error message
 */
export function assertNoControlChars(value: string, fieldName: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === CR) {
      throw new SmtpMessageError(`${fieldName} contains a carriage return (CR)`);
    }
    if (code === LF) {
      throw new SmtpMessageError(`${fieldName} contains a line feed (LF)`);
    }
    if (code === NUL) {
      throw new SmtpMessageError(`${fieldName} contains a NUL byte`);
    }
  }
}

/**
 * Reject any C0/C1 control character (other than TAB) in header content. Used
 * for header field values where control characters have no legal place. CR/LF
 * are already rejected by {@link assertNoControlChars}; this is a stricter check
 * used where appropriate.
 */
export function assertNoDangerousControls(value: string, fieldName: string): void {
  assertNoControlChars(value, fieldName);
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    // Allow TAB (0x09). Reject other C0 controls and DEL.
    if ((code < 0x20 && code !== 0x09) || code === 0x7f) {
      throw new SmtpMessageError(
        `${fieldName} contains a control character (0x${code.toString(16)})`,
      );
    }
  }
}

/** True if the string is pure 7-bit ASCII. */
export function isAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

/**
 * Validate a header field name (ftext): printable US-ASCII 33-126 excluding
 * colon. RFC 5322 sec 2.2. Rejects space, control chars, colon, and non-ASCII.
 */
export function assertValidHeaderName(name: string): void {
  if (name.length === 0) {
    throw new SmtpMessageError('header name is empty');
  }
  for (let i = 0; i < name.length; i++) {
    const code = name.charCodeAt(i);
    // ftext = %d33-57 / %d59-126 (printable ASCII except ':' which is 58)
    if (code < 33 || code > 126 || code === 58) {
      throw new SmtpMessageError(
        `invalid header name ${JSON.stringify(name)}: contains an illegal character`,
      );
    }
  }
}

/**
 * Structured result of splitting an address into local-part and domain. Only
 * used for size and grammar checks; the control-char gate runs first.
 */
export interface SplitAddress {
  localPart: string;
  domain: string;
  /** True when the local part was a quoted-string form. */
  quotedLocal: boolean;
}

/**
 * Split an addr-spec into local-part and domain at the last unquoted '@'.
 * Handles the quoted-string local-part form so that a legally quoted local part
 * containing an '@' is split correctly. This is correctness-only; the control
 * character gate is applied by the caller before and after this.
 */
export function splitAddress(address: string): SplitAddress {
  if (address.length === 0) {
    throw new SmtpMessageError('address is empty');
  }
  let inQuotes = false;
  let atIndex = -1;
  let quotedLocal = false;
  for (let i = 0; i < address.length; i++) {
    const ch = address[i];
    if (ch === '"' && (i === 0 || address[i - 1] !== '\\')) {
      inQuotes = !inQuotes;
      if (i === 0) quotedLocal = true;
    } else if (ch === '@' && !inQuotes) {
      atIndex = i;
    }
  }
  if (inQuotes) {
    throw new SmtpMessageError('address has an unbalanced quote in the local part');
  }
  if (atIndex <= 0 || atIndex === address.length - 1) {
    throw new SmtpMessageError(`address ${JSON.stringify(address)} is missing a local part or domain`);
  }
  return {
    localPart: address.slice(0, atIndex),
    domain: address.slice(atIndex + 1),
    quotedLocal,
  };
}

/**
 * Validate an addr-spec used as an envelope path or header address. Applies the
 * control-char gate first, then RFC 5321 size limits, then a domain grammar
 * check. Throws on any violation (fail closed). Does not mutate the value.
 *
 * @param address the raw address (no angle brackets)
 * @param fieldName a non-secret label for error messages
 * @param opts.allowNonAsciiLocal when false (default), a non-ASCII local part is
 *   rejected unless SMTPUTF8 handling upstream permits it
 */
export function validateAddress(
  address: string,
  fieldName: string,
  opts: { requireAscii?: boolean } = {},
): SplitAddress {
  assertNoControlChars(address, fieldName);
  if (address.length > LIMITS.emailAddress) {
    throw new SmtpMessageError(
      `${fieldName} exceeds the maximum address length of ${LIMITS.emailAddress}`,
    );
  }
  const split = splitAddress(address);
  if (split.localPart.length > LIMITS.localPart) {
    throw new SmtpMessageError(
      `${fieldName} local part exceeds ${LIMITS.localPart} octets`,
    );
  }
  if (split.domain.length > LIMITS.domain) {
    throw new SmtpMessageError(`${fieldName} domain exceeds ${LIMITS.domain} octets`);
  }
  if (address.length > LIMITS.path - 2) {
    // Path including angle brackets must be <= 256.
    throw new SmtpMessageError(`${fieldName} exceeds the maximum path length`);
  }
  validateDomainSyntax(split.domain, fieldName);
  if (opts.requireAscii && !isAscii(split.localPart)) {
    throw new SmtpMessageError(
      `${fieldName} has a non-ASCII local part but the server does not advertise SMTPUTF8`,
    );
  }
  return split;
}

/**
 * Validate the domain part: either a dot-atom (labels of letters, digits, and
 * hyphens) or an address literal in brackets ([192.0.2.1] or [IPv6:...]).
 */
export function validateDomainSyntax(domain: string, fieldName: string): void {
  if (domain.length === 0) {
    throw new SmtpMessageError(`${fieldName} has an empty domain`);
  }
  if (domain.startsWith('[') && domain.endsWith(']')) {
    // Address literal. Accept a bounded set of literal characters.
    const inner = domain.slice(1, -1);
    if (!/^[A-Za-z0-9:.]+$/.test(inner)) {
      throw new SmtpMessageError(`${fieldName} has a malformed address literal`);
    }
    return;
  }
  // Dot-atom domain. Labels separated by dots, each label letters/digits/hyphen,
  // not starting or ending with a hyphen, no empty labels.
  const labels = domain.split('.');
  const labelPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
  for (const label of labels) {
    if (label.length === 0) {
      throw new SmtpMessageError(`${fieldName} has an empty domain label`);
    }
    if (!labelPattern.test(label)) {
      throw new SmtpMessageError(`${fieldName} has an invalid domain label`);
    }
  }
}

/**
 * Validate the argument to EHLO/HELO. Must be a valid FQDN or address literal
 * with no control characters. The client identity is not secret.
 */
export function validateClientId(id: string): void {
  assertNoControlChars(id, 'client identity');
  if (id.length === 0 || id.length > 255) {
    throw new SmtpMessageError('client identity has an invalid length');
  }
  validateDomainSyntax(id, 'client identity');
}
