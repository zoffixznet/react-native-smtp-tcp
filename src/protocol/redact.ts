/**
 * Redaction helpers. Every string that reaches a logger passes through here so
 * no credential, token, or base64 AUTH payload is ever emitted.
 */

/**
 * Redact an outgoing command line before logging. AUTH command arguments and
 * bare base64 continuation lines (AUTH exchange responses) become "***". Other
 * commands pass through unchanged.
 */
export function redactCommand(line: string): string {
  const trimmed = line.replace(/\r?\n$/, '');
  // AUTH <mechanism> [initial-response] -> keep the verb and mechanism, redact
  // any initial response argument.
  const authMatch = /^(AUTH)\s+(\S+)(\s+.*)?$/i.exec(trimmed);
  if (authMatch) {
    const rest = authMatch[3] ? ' ***' : '';
    return `${authMatch[1]} ${authMatch[2]}${rest}`;
  }
  return trimmed;
}

/**
 * Redact a continuation line sent during an AUTH exchange (a bare base64 blob or
 * the "*" cancel). Always redacted to "***" since it may carry credentials.
 */
export function redactAuthExchangeLine(): string {
  return '***';
}

/**
 * Redact a server reply that may echo a base64 challenge. The 3-digit code and
 * enhanced status are safe to show; the free text after them is redacted only
 * during an AUTH exchange to be safe.
 */
export function redactAuthReply(line: string): string {
  const m = /^(\d{3}[ -])/.exec(line);
  if (m) return `${m[1]}***`;
  return '***';
}
