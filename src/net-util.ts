/**
 * Tiny, dependency-free helpers for recognizing IP literals. Kept separate so
 * the pure logic has no Node/RN dependency.
 */

/** True if the string is an IPv4 dotted-quad. */
export function isIPv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    if (n < 0 || n > 255) return false;
    if (part.length > 1 && part[0] === '0') return false;
  }
  return true;
}

/** True if the string is a plausible IPv6 literal (bounded, non-backtracking). */
export function isIPv6(value: string): boolean {
  // Reject anything with characters outside the IPv6 set quickly.
  if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
  // Must contain at least one colon.
  if (value.indexOf(':') === -1) return false;
  // At most one "::" compression.
  const doubleColon = value.split('::').length - 1;
  if (doubleColon > 1) return false;
  const groups = value.split(':');
  if (groups.length > 8) return false;
  for (const g of groups) {
    if (g.length > 4) return false;
  }
  return true;
}

/** True if the string is an IPv4 or IPv6 literal. */
export function isIP(value: string): boolean {
  return isIPv4(value) || isIPv6(value);
}
