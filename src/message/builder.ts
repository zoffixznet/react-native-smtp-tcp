/**
 * RFC 5322 / MIME message builder.
 *
 * Produces the DATA payload (headers, blank line, body) with CRLF line endings.
 * Enforces the injection defenses (control-char rejection, envelope/header
 * separation), RFC 2047 encoding, MIME structure, and mandatory headers. The
 * output is dot-stuffed only at transmission time by the protocol layer, so the
 * builder returns the un-stuffed content and its octet size.
 */

import { Buffer } from 'buffer';
import { SmtpMessageError } from '../protocol/errors';
import type { Address } from './address';
import { normalizeAddress } from './address';
import {
  assertNoControlChars,
  assertNoDangerousControls,
  assertValidHeaderName,
  isAscii,
  validateAddress,
  LIMITS,
} from './validate';
import {
  base64Wrapped,
  encodeHeaderWord,
  foldHeaderLine,
  quotedPrintable,
} from './encoding';

const CRLF = '\r\n';

/** An attachment to include in the message. */
export interface Attachment {
  /** File name shown to the recipient. Control chars are rejected. */
  filename: string;
  /** Raw bytes, or a base64 string when `encoding` is 'base64'. */
  content: string | Uint8Array | Buffer;
  /** MIME content type. Defaults to application/octet-stream. */
  contentType?: string;
  /** Set to 'base64' when `content` is already a base64 string. */
  encoding?: 'base64' | 'binary';
  /** Optional Content-ID for inline attachments. */
  contentId?: string;
}

/** A message to build and send. */
export interface MailMessage {
  from: string | Address;
  to: Array<string | Address>;
  cc?: Array<string | Address>;
  bcc?: Array<string | Address>;
  replyTo?: string | Address;
  subject?: string;
  text?: string;
  html?: string;
  attachments?: Attachment[];
  /** Extra headers. Names and values are validated; injection is rejected. */
  headers?: Record<string, string>;
  /** Override the generated Message-ID. Must be a full <id@domain> token. */
  messageId?: string;
  /** Override the Date header value (must be a valid RFC 5322 date string). */
  date?: Date;
}

/** Server capabilities that affect how the message is encoded. */
export interface EncodeContext {
  smtpUtf8: boolean;
  eightBitMime: boolean;
}

/** Result of building a message. */
export interface BuiltMessage {
  /** The full DATA payload (headers + blank line + body), CRLF line endings. */
  data: string;
  /** Octet size of `data` (used for the SIZE extension). */
  sizeBytes: number;
  /** The generated or provided Message-ID (with angle brackets). */
  messageId: string;
  /** Envelope sender (addr-spec, no brackets). */
  envelopeFrom: string;
  /** Envelope recipients (addr-spec, no brackets), deduplicated in order. */
  envelopeTo: string[];
  /** True if any envelope address needs SMTPUTF8. */
  requiresSmtpUtf8: boolean;
}

/**
 * A cryptographically strong random hex string used for boundaries and
 * Message-IDs. Uses the platform crypto where available and falls back to a
 * bounded Math.random loop only if crypto is entirely unavailable.
 */
function randomHex(bytes: number): string {
  // Node and modern RN provide global crypto.getRandomValues.
  const g = globalThis as unknown as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } };
  const arr = new Uint8Array(bytes);
  if (g.crypto && typeof g.crypto.getRandomValues === 'function') {
    g.crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  let hex = '';
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
  return hex;
}

/** Format a Date per RFC 5322 sec 3.3 with a correct numeric zone offset. */
export function formatDate(date: Date): string {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];
  const pad = (n: number, w = 2) => String(Math.abs(n)).padStart(w, '0');
  const offsetMin = -date.getTimezoneOffset();
  const sign = offsetMin >= 0 ? '+' : '-';
  const offH = pad(Math.floor(Math.abs(offsetMin) / 60));
  const offM = pad(Math.abs(offsetMin) % 60);
  return (
    `${days[date.getDay()]}, ${pad(date.getDate())} ${months[date.getMonth()]} ` +
    `${date.getFullYear()} ${pad(date.getHours())}:${pad(date.getMinutes())}:` +
    `${pad(date.getSeconds())} ${sign}${offH}${offM}`
  );
}

/** Format an address for a header ("Name <addr>"), RFC 2047-encoding the name. */
function formatHeaderAddress(addr: Address): string {
  const addrSpec = addr.address;
  if (addr.name && addr.name.length > 0) {
    // The display name is control-char checked, then RFC 2047 encoded if needed.
    assertNoControlChars(addr.name, 'display name');
    if (isAscii(addr.name)) {
      // Quote the display name if it contains specials so it stays a phrase.
      if (/[()<>@,;:\\".[\]]/.test(addr.name)) {
        const escaped = addr.name.replace(/(["\\])/g, '\\$1');
        return `"${escaped}" <${addrSpec}>`;
      }
      return `${addr.name} <${addrSpec}>`;
    }
    // Non-ASCII display name: encoded-word (never inside the addr-spec).
    return `${encodeHeaderWord(addr.name)} <${addrSpec}>`;
  }
  return `<${addrSpec}>`;
}

/** Validate the addr-spec of a header address and its display name. */
function validateHeaderAddress(addr: Address, fieldName: string, ctx: EncodeContext): void {
  validateAddress(addr.address, fieldName, { requireAscii: !ctx.smtpUtf8 });
  if (addr.name) {
    assertNoControlChars(addr.name, `${fieldName} display name`);
  }
}

interface HeaderLine {
  name: string;
  value: string;
}

/** Serialize header lines with folding, in the order given. */
function serializeHeaders(headers: HeaderLine[]): string {
  return headers.map((h) => foldHeaderLine(h.name, h.value)).join(CRLF);
}

/** Decide the transfer encoding for a text part. */
function encodeTextPart(content: string, ctx: EncodeContext): { encoding: string; body: string } {
  if (isAscii(content)) {
    // Pure ASCII: 7-bit clean. Quoted-printable is still safe and keeps long
    // lines within limits, so use QP when any line would exceed the limit.
    const hasLongLine = content.split(CRLF).some((l) => Buffer.byteLength(l, 'utf8') > LIMITS.textLine);
    if (hasLongLine) {
      return { encoding: 'quoted-printable', body: quotedPrintable(content) };
    }
    return { encoding: '7bit', body: content };
  }
  // Non-ASCII text.
  if (ctx.eightBitMime) {
    // 8BITMIME advertised: still send quoted-printable to keep lines bounded and
    // avoid raw control-byte smuggling; this is 7-bit safe and always valid.
    return { encoding: 'quoted-printable', body: quotedPrintable(content) };
  }
  // 8BITMIME not advertised: MUST NOT send raw 8-bit octets. Use QP.
  return { encoding: 'quoted-printable', body: quotedPrintable(content) };
}

/** Normalize lone CR and lone LF in user text to CRLF. */
export function normalizeNewlines(text: string): string {
  return text.replace(/\r\n|\r|\n/g, CRLF);
}

/**
 * Build the full message. Applies all validation and encoding. Throws (fail
 * closed) on any injection attempt or limit breach before producing any output.
 */
export function buildMessage(message: MailMessage, ctx: EncodeContext): BuiltMessage {
  // --- Envelope and address validation -------------------------------------
  const from = normalizeAddress(message.from, 'from');
  validateHeaderAddress(from, 'from', ctx);

  if (!Array.isArray(message.to) || message.to.length === 0) {
    throw new SmtpMessageError('at least one recipient is required in "to"');
  }
  const toAddrs = message.to.map((t) => normalizeAddress(t, 'to'));
  const ccAddrs = (message.cc ?? []).map((t) => normalizeAddress(t, 'cc'));
  const bccAddrs = (message.bcc ?? []).map((t) => normalizeAddress(t, 'bcc'));
  for (const a of toAddrs) validateHeaderAddress(a, 'to', ctx);
  for (const a of ccAddrs) validateHeaderAddress(a, 'cc', ctx);
  for (const a of bccAddrs) validateHeaderAddress(a, 'bcc', ctx);

  const replyTo = message.replyTo ? normalizeAddress(message.replyTo, 'replyTo') : undefined;
  if (replyTo) validateHeaderAddress(replyTo, 'replyTo', ctx);

  // Envelope recipients: explicit, validated list. Never derived from headers.
  const envelopeTo: string[] = [];
  const seen = new Set<string>();
  for (const a of [...toAddrs, ...ccAddrs, ...bccAddrs]) {
    if (!seen.has(a.address)) {
      seen.add(a.address);
      envelopeTo.push(a.address);
    }
  }
  if (envelopeTo.length > LIMITS.maxRecipients) {
    throw new SmtpMessageError(
      `too many recipients (${envelopeTo.length}); the limit is ${LIMITS.maxRecipients}`,
    );
  }

  const requiresSmtpUtf8 =
    !isAscii(from.address) || envelopeTo.some((a) => !isAscii(a));

  // --- Header assembly ------------------------------------------------------
  const headers: HeaderLine[] = [];

  const messageId = message.messageId
    ? validateMessageId(message.messageId, from.address)
    : `<${randomHex(16)}.${Date.now().toString(36)}@${domainOf(from.address)}>`;

  const date = message.date ?? new Date();
  headers.push({ name: 'Date', value: formatDate(date) });
  headers.push({ name: 'From', value: formatHeaderAddress(from) });
  headers.push({ name: 'To', value: toAddrs.map(formatHeaderAddress).join(', ') });
  if (ccAddrs.length > 0) {
    headers.push({ name: 'Cc', value: ccAddrs.map(formatHeaderAddress).join(', ') });
  }
  // Bcc recipients are in the envelope only; never emitted as a header.
  if (replyTo) {
    headers.push({ name: 'Reply-To', value: formatHeaderAddress(replyTo) });
  }
  headers.push({ name: 'Message-ID', value: messageId });
  const subject = message.subject ?? '';
  // Unconditional control-char gate before any encoding: CR/LF/NUL in a header
  // value must be rejected, never silently encoded away.
  assertNoControlChars(subject, 'subject');
  headers.push({ name: 'Subject', value: encodeHeaderWord(subject) });
  headers.push({ name: 'MIME-Version', value: '1.0' });

  // Extra user headers. Reject reserved header names to avoid duplicates and
  // reject any control-character injection in names or values.
  const reserved = new Set([
    'date', 'from', 'to', 'cc', 'bcc', 'reply-to', 'message-id',
    'subject', 'mime-version', 'content-type', 'content-transfer-encoding',
  ]);
  if (message.headers) {
    for (const rawName of safeOwnKeys(message.headers)) {
      const value = message.headers[rawName];
      assertValidHeaderName(rawName);
      if (reserved.has(rawName.toLowerCase())) {
        throw new SmtpMessageError(`header "${rawName}" is managed by the library and cannot be overridden`);
      }
      if (typeof value !== 'string') {
        throw new SmtpMessageError(`header "${rawName}" must have a string value`);
      }
      assertNoDangerousControls(value, `header "${rawName}" value`);
      headers.push({ name: rawName, value: encodeHeaderWord(value) });
    }
  }

  // --- Body / MIME assembly -------------------------------------------------
  const { bodyHeaders, body } = buildBody(message, ctx);
  const allHeaders = serializeHeaders([...headers, ...bodyHeaders]);

  const data = allHeaders + CRLF + CRLF + body;
  assertNoBareLineBreaks(data);

  return {
    data,
    sizeBytes: Buffer.byteLength(data, 'utf8'),
    messageId,
    envelopeFrom: from.address,
    envelopeTo,
    requiresSmtpUtf8,
  };
}

/** Build the MIME body and the content headers that describe it. */
function buildBody(message: MailMessage, ctx: EncodeContext): {
  bodyHeaders: HeaderLine[];
  body: string;
} {
  const text = message.text !== undefined ? normalizeNewlines(message.text) : undefined;
  const html = message.html !== undefined ? normalizeNewlines(message.html) : undefined;
  const attachments = message.attachments ?? [];

  if (text === undefined && html === undefined && attachments.length === 0) {
    throw new SmtpMessageError('message has no text, html, or attachments');
  }

  // The main content is either a single text part, a single html part, or a
  // multipart/alternative of both.
  const alternative = buildAlternative(text, html, ctx);

  if (attachments.length === 0) {
    return { bodyHeaders: alternative.headers, body: alternative.body };
  }

  // Wrap the alternative (or single part) plus attachments in multipart/mixed.
  const boundary = makeBoundary();
  const parts: string[] = [];

  // First part: the message content.
  parts.push(
    serializeHeaders(alternative.headers) + CRLF + CRLF + alternative.body,
  );

  for (const att of attachments) {
    parts.push(buildAttachmentPart(att));
  }

  assertBoundaryAbsent(boundary, parts);
  const body = renderMultipart(boundary, parts);
  return {
    bodyHeaders: [
      { name: 'Content-Type', value: `multipart/mixed; boundary="${boundary}"` },
    ],
    body,
  };
}

/** Build the message content: single part or multipart/alternative. */
function buildAlternative(
  text: string | undefined,
  html: string | undefined,
  ctx: EncodeContext,
): { headers: HeaderLine[]; body: string } {
  const textPart = text !== undefined ? encodeTextPart(text, ctx) : undefined;
  const htmlPart = html !== undefined ? encodeTextPart(html, ctx) : undefined;

  if (textPart && !htmlPart) {
    return {
      headers: [
        { name: 'Content-Type', value: 'text/plain; charset=UTF-8' },
        { name: 'Content-Transfer-Encoding', value: textPart.encoding },
      ],
      body: textPart.body,
    };
  }
  if (htmlPart && !textPart) {
    return {
      headers: [
        { name: 'Content-Type', value: 'text/html; charset=UTF-8' },
        { name: 'Content-Transfer-Encoding', value: htmlPart.encoding },
      ],
      body: htmlPart.body,
    };
  }
  // Both present: multipart/alternative, text first (RFC 2046 sec 5.1.4).
  const boundary = makeBoundary();
  const parts = [
    `Content-Type: text/plain; charset=UTF-8${CRLF}` +
      `Content-Transfer-Encoding: ${textPart!.encoding}${CRLF}${CRLF}` +
      textPart!.body,
    `Content-Type: text/html; charset=UTF-8${CRLF}` +
      `Content-Transfer-Encoding: ${htmlPart!.encoding}${CRLF}${CRLF}` +
      htmlPart!.body,
  ];
  assertBoundaryAbsent(boundary, parts);
  const body = renderMultipart(boundary, parts);
  return {
    headers: [
      { name: 'Content-Type', value: `multipart/alternative; boundary="${boundary}"` },
    ],
    body,
  };
}

/** Build a single attachment MIME part (always base64, always 7-bit safe). */
function buildAttachmentPart(att: Attachment): string {
  assertNoControlChars(att.filename, 'attachment filename');
  if (att.filename.length === 0) {
    throw new SmtpMessageError('attachment filename is empty');
  }
  const contentType = att.contentType ?? 'application/octet-stream';
  assertNoControlChars(contentType, 'attachment content type');

  let bytes: Buffer;
  if (typeof att.content === 'string') {
    if (att.encoding === 'base64') {
      bytes = Buffer.from(att.content, 'base64');
    } else {
      bytes = Buffer.from(att.content, 'utf8');
    }
  } else {
    bytes = Buffer.from(att.content);
  }

  const encodedName = encodeHeaderWord(att.filename);
  const headers: HeaderLine[] = [
    { name: 'Content-Type', value: `${contentType}; name="${filenameParam(att.filename)}"` },
    { name: 'Content-Transfer-Encoding', value: 'base64' },
    {
      name: 'Content-Disposition',
      value: `attachment; filename="${filenameParam(att.filename)}"`,
    },
  ];
  if (!isAscii(att.filename)) {
    // Use the encoded-word form in a separate, well-known place if non-ASCII.
    headers[0] = { name: 'Content-Type', value: `${contentType}; name="${encodedName}"` };
    headers[2] = {
      name: 'Content-Disposition',
      value: `attachment; filename="${encodedName}"`,
    };
  }
  if (att.contentId) {
    assertNoControlChars(att.contentId, 'attachment content id');
    headers.push({ name: 'Content-ID', value: `<${att.contentId}>` });
  }
  return serializeHeaders(headers) + CRLF + CRLF + base64Wrapped(bytes);
}

/** Escape a filename for use inside a quoted MIME parameter. */
function filenameParam(filename: string): string {
  return filename.replace(/(["\\])/g, '\\$1');
}

/** Render a multipart body from a boundary and pre-serialized parts. */
function renderMultipart(boundary: string, parts: string[]): string {
  let out = '';
  for (const part of parts) {
    out += `--${boundary}${CRLF}${part}${CRLF}`;
  }
  out += `--${boundary}--${CRLF}`;
  return out;
}

/**
 * A random, collision-free boundary. 16 random bytes (128 bits) is far beyond
 * any collision risk, and the short prefix keeps the Content-Type header on one
 * line for the common single-alternative case.
 */
function makeBoundary(): string {
  return `=_rnsmtp_${randomHex(16)}`;
}

/** Ensure the chosen boundary does not appear inside any part's content. */
function assertBoundaryAbsent(boundary: string, parts: string[]): void {
  for (const part of parts) {
    if (part.includes(boundary)) {
      // Astronomically unlikely with 18 random bytes; still fail closed.
      throw new SmtpMessageError('internal: boundary collision detected');
    }
  }
}

/** Validate a user-provided Message-ID token. */
function validateMessageId(id: string, fromAddress: string): string {
  assertNoControlChars(id, 'messageId');
  const trimmed = id.trim();
  if (!/^<[^<>@\s]+@[^<>@\s]+>$/.test(trimmed)) {
    throw new SmtpMessageError('messageId must be a single <id@domain> token');
  }
  void fromAddress;
  return trimmed;
}

/** Extract the domain of an addr-spec for Message-ID generation. */
function domainOf(address: string): string {
  const at = address.lastIndexOf('@');
  return at >= 0 ? address.slice(at + 1) : 'localhost';
}

/**
 * Final assertion over the serialized stream: zero bare CR and zero bare LF.
 * Every line break must be a full CRLF pair introduced by the library.
 */
export function assertNoBareLineBreaks(data: string): void {
  for (let i = 0; i < data.length; i++) {
    const code = data.charCodeAt(i);
    if (code === 0x0d) {
      if (data.charCodeAt(i + 1) !== 0x0a) {
        throw new SmtpMessageError('serialized message contains a bare CR');
      }
      i++; // skip the LF of a valid CRLF
    } else if (code === 0x0a) {
      throw new SmtpMessageError('serialized message contains a bare LF');
    }
  }
}

/**
 * Enumerate own enumerable string keys of a plain object while skipping
 * prototype-pollution vectors. Never returns __proto__, constructor, prototype.
 */
export function safeOwnKeys(obj: Record<string, unknown>): string[] {
  const dangerous = new Set(['__proto__', 'constructor', 'prototype']);
  return Object.keys(obj).filter((k) => !dangerous.has(k));
}
