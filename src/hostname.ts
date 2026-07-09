/**
 * Hostname identity verification against a certificate's subjectAltName dNSName
 * (with CN as a legacy fallback), performed only after PKIX path validation.
 *
 * On Node, tls.connect already performs SAN/CN matching against `servername`
 * when rejectUnauthorized is true, so this module's checks are a defense in
 * depth and are the primary identity check on platforms where the socket does
 * not expose SNI (bare-IP hosts). It uses parsed certificate fields provided by
 * the adapter.
 */

import { isIP } from './net-util';

/** Wildcard-aware match of a hostname against a single dNSName pattern. */
export function matchHostname(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase().trim();
  if (p.length === 0) return false;
  if (p === h) return true;
  // Only a single leading "*." wildcard in the leftmost label is allowed, and it
  // must not match across a dot boundary.
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    const firstDot = h.indexOf('.');
    if (firstDot === -1) return false;
    const hostSuffix = h.slice(firstDot); // ".example.com"
    // The wildcard must not match a bare label containing a dot.
    return hostSuffix === suffix && h.slice(0, firstDot).length > 0;
  }
  return false;
}

/**
 * Verify an expected hostname against the SAN dNSName list (and CN fallback).
 * Returns true on a match. IP hosts are matched literally against IP SANs only.
 */
export function verifyHostname(
  expectedHost: string,
  altNames: string[],
  commonName?: string,
): boolean {
  if (isIP(expectedHost)) {
    // For an IP target, only an exact IP SAN match is acceptable.
    return altNames.some((n) => n.toLowerCase() === expectedHost.toLowerCase());
  }
  for (const name of altNames) {
    if (matchHostname(expectedHost, name)) return true;
  }
  // CN fallback only when there are no dNSName SANs (legacy behavior).
  const hasDnsSan = altNames.length > 0;
  if (!hasDnsSan && commonName && matchHostname(expectedHost, commonName)) {
    return true;
  }
  return false;
}
