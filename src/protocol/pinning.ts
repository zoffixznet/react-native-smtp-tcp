/**
 * SPKI pinning comparison. Pure logic over a peer certificate view provided by
 * the adapter. The adapter supplies the DER-encoded SubjectPublicKeyInfo (or a
 * sha256 fingerprint) after the handshake; this module computes/compares the
 * base64 SHA-256 of the SPKI and reports a match.
 *
 * Hashing uses the platform crypto (Node crypto / RN global). No hand-rolled
 * crypto. If no SPKI is available from the platform, pinning cannot be enforced
 * and the caller treats that as a failure when a pin was requested.
 */

import { Buffer } from 'buffer';
import type { PeerCertificate } from './types';

/** Injected SHA-256 function so the engine stays platform-agnostic. */
export type Sha256 = (data: Uint8Array) => Uint8Array;

/**
 * Compute the base64 SHA-256 of the certificate's SPKI, if available.
 * Returns null when the platform did not expose a usable public key.
 */
export function computeSpkiSha256(
  cert: PeerCertificate | undefined,
  sha256: Sha256,
): string | null {
  if (!cert) return null;
  if (cert.pubkey && cert.pubkey.length > 0) {
    return Buffer.from(sha256(cert.pubkey)).toString('base64');
  }
  return null;
}

/**
 * Compare a computed SPKI hash against the configured pin. Both are base64
 * strings. Comparison is constant-length safe (lengths compared first, then a
 * byte-wise comparison that does not short-circuit on the first difference).
 */
export function pinMatches(computed: string | null, configured: string): boolean {
  if (computed === null) return false;
  const a = Buffer.from(computed, 'base64');
  const b = Buffer.from(configured, 'base64');
  if (a.length === 0 || b.length === 0) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
