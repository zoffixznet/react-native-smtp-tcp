/**
 * Optional certificate-fingerprint pinning. Pure comparison over the peer
 * certificate view the adapter exposes after the handshake.
 *
 * The pin is the SHA-256 fingerprint of the leaf certificate. It is compared
 * against the platform's `fingerprint256` field. Both the configured pin and the
 * platform value are normalized to lowercase hex without separators before a
 * length-checked, non-short-circuiting comparison, so either colon-separated hex
 * or a plain hex string is accepted.
 *
 * Pinning is layered on top of (never instead of) the default chain and hostname
 * verification the TLS handshake performs. It is entirely optional.
 */

import type { PeerCertificate } from './types';

/**
 * Normalize a fingerprint to lowercase hex with no separators. Returns null when
 * the input is empty or contains no hex digits.
 */
export function normalizeFingerprint(value: string | undefined | null): string | null {
  if (!value) return null;
  const hex = value.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length === 0) return null;
  return hex;
}

/**
 * Compare the peer certificate's SHA-256 fingerprint against the configured pin.
 * Returns false when either side is missing or unparseable. The comparison is
 * length-checked and does not short-circuit on the first differing character.
 */
export function certFingerprintMatches(
  cert: PeerCertificate | undefined,
  configuredPin: string,
): boolean {
  const expected = normalizeFingerprint(configuredPin);
  const actual = normalizeFingerprint(cert?.fingerprint256);
  if (expected === null || actual === null) return false;
  if (expected.length !== actual.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  }
  return diff === 0;
}
