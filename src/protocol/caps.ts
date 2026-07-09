/**
 * Default DoS caps and layered timeouts. These are floors derived from RFC 5321
 * sec 4.5.3.1 (line/size limits) and sec 4.5.3.2 (client timeout minimums),
 * raised to sensible, bounded values for a mobile submission client.
 */

import type { Caps, Timeouts } from './types';

export const DEFAULT_CAPS: Caps = {
  // Above the 512-octet spec minimum, generous enough for real servers.
  maxLineBytes: 8 * 1024,
  // A full multiline reply is bounded well under this.
  maxReplyBytes: 64 * 1024,
  // No legitimate EHLO advertises hundreds of continuation lines.
  maxContinuationLines: 200,
  // A correct server never leaves more than one un-consumed reply outside the
  // greeting race; a small cap turns an unsolicited-reply flood into a bounded,
  // fail-closed error instead of unbounded memory growth.
  maxQueuedReplies: 16,
};

export const DEFAULT_TIMEOUTS: Timeouts = {
  connectMs: 15_000,
  greetingMs: 15_000,
  idleMs: 30_000,
  overallMs: 60_000,
};

/**
 * Merge caps/timeouts safely (prototype-pollution-safe). Only known keys are
 * copied; user objects are never spread wholesale.
 */
export function mergeCaps(base: Caps, override?: Partial<Caps>): Caps {
  if (!override) return { ...base };
  return {
    maxLineBytes: pickPositive(override.maxLineBytes, base.maxLineBytes),
    maxReplyBytes: pickPositive(override.maxReplyBytes, base.maxReplyBytes),
    maxContinuationLines: pickPositive(override.maxContinuationLines, base.maxContinuationLines),
    maxQueuedReplies: pickPositive(override.maxQueuedReplies, base.maxQueuedReplies),
  };
}

export function mergeTimeouts(base: Timeouts, override?: Partial<Timeouts>): Timeouts {
  if (!override) return { ...base };
  return {
    connectMs: pickPositive(override.connectMs, base.connectMs),
    greetingMs: pickPositive(override.greetingMs, base.greetingMs),
    idleMs: pickPositive(override.idleMs, base.idleMs),
    overallMs: pickPositive(override.overallMs, base.overallMs),
  };
}

function pickPositive(value: number | undefined, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return value;
  }
  return fallback;
}
