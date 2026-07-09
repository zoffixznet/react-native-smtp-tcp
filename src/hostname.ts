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

/**
 * A small set of well-known multi-label public suffixes. A wildcard whose base
 * (the labels after "*.") is a public suffix must be rejected, because such a
 * certificate would otherwise validate an entire registry (e.g. "*.co.uk"
 * matching every ".co.uk" host). This is not an exhaustive Public Suffix List;
 * it covers the common two- and three-label registry suffixes so the practical
 * abuse cases are blocked without pulling in a large data dependency. The
 * single-label case ("*.com") is handled separately by a minimum-label rule.
 */
const KNOWN_PUBLIC_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.za', 'org.za', 'net.za', 'gov.za',
  'com.mx', 'com.tr', 'com.ar', 'com.sg', 'com.hk', 'com.tw',
]);

/**
 * True when a "*." wildcard whose base (the domain after the wildcard label) is
 * `base` is too broad to be a valid identity: it would match a whole registry.
 * A valid wildcard must leave at least two labels below it AND its base must not
 * be a known public suffix. RFC 6125 sec 7.2 / the CA/Browser Baseline
 * Requirements forbid wildcards in a public-suffix / effective-TLD position.
 */
function isDangerousWildcardBase(base: string): boolean {
  // base is the pattern with the leading "*." removed, e.g. "example.com".
  const labels = base.split('.').filter((l) => l.length > 0);
  // Need at least two labels below the wildcard (rejects "*.com").
  if (labels.length < 2) return true;
  // Reject when the whole base is itself a known multi-label public suffix
  // (rejects "*.co.uk"): the registrable label below the wildcard is missing.
  if (KNOWN_PUBLIC_SUFFIXES.has(base)) return true;
  return false;
}

/** Wildcard-aware match of a hostname against a single dNSName pattern. */
export function matchHostname(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase().trim();
  if (p.length === 0) return false;
  if (p === h) return true;
  // Only a single leading "*." wildcard in the leftmost label is allowed, and it
  // must not match across a dot boundary. A pattern with any other "*" (embedded
  // or trailing) is not a legal single-leftmost-label wildcard and is rejected.
  if (p.startsWith('*.') && p.indexOf('*', 1) === -1) {
    const base = p.slice(2); // "example.com" for "*.example.com"
    // Refuse wildcards that sit in a public-suffix / TLD position.
    if (isDangerousWildcardBase(base)) return false;
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
