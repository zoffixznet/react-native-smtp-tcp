import { describe, it, expect } from 'vitest';
import { mergeCaps, mergeTimeouts, DEFAULT_CAPS, DEFAULT_TIMEOUTS } from '../src/protocol/caps';
import { normalizeAddress, stripBrackets, angleWrap } from '../src/message/address';
import { SmtpMessageError } from '../src/protocol/errors';

describe('caps and timeout merging', () => {
  it('returns a copy of the base when no override', () => {
    expect(mergeCaps(DEFAULT_CAPS)).toEqual(DEFAULT_CAPS);
    expect(mergeTimeouts(DEFAULT_TIMEOUTS)).toEqual(DEFAULT_TIMEOUTS);
  });

  it('applies positive overrides and ignores invalid ones', () => {
    const caps = mergeCaps(DEFAULT_CAPS, {
      maxLineBytes: 1000,
      maxReplyBytes: -1, // invalid, keep base
      maxContinuationLines: 0, // invalid (not > 0), keep base
      maxQueuedReplies: 32,
    });
    expect(caps.maxLineBytes).toBe(1000);
    expect(caps.maxReplyBytes).toBe(DEFAULT_CAPS.maxReplyBytes);
    expect(caps.maxContinuationLines).toBe(DEFAULT_CAPS.maxContinuationLines);
    expect(caps.maxQueuedReplies).toBe(32);
    // An invalid override keeps the base default.
    expect(mergeCaps(DEFAULT_CAPS, { maxQueuedReplies: -5 }).maxQueuedReplies).toBe(
      DEFAULT_CAPS.maxQueuedReplies,
    );

    const t = mergeTimeouts(DEFAULT_TIMEOUTS, {
      connectMs: 5000,
      greetingMs: Number.NaN, // invalid, keep base
      idleMs: 0, // invalid, keep base
      overallMs: 99000,
    });
    expect(t.connectMs).toBe(5000);
    expect(t.greetingMs).toBe(DEFAULT_TIMEOUTS.greetingMs);
    expect(t.idleMs).toBe(DEFAULT_TIMEOUTS.idleMs);
    expect(t.overallMs).toBe(99000);
  });
});

describe('address normalization', () => {
  it('normalizes strings and objects', () => {
    expect(normalizeAddress('me@example.com', 'x')).toEqual({ address: 'me@example.com' });
    expect(normalizeAddress({ name: 'Me', address: 'me@example.com' }, 'x')).toEqual({
      name: 'Me',
      address: 'me@example.com',
    });
    expect(normalizeAddress('<me@example.com>', 'x')).toEqual({ address: 'me@example.com' });
  });

  it('rejects invalid inputs', () => {
    // @ts-expect-error deliberately invalid
    expect(() => normalizeAddress(42, 'x')).toThrow(SmtpMessageError);
    // @ts-expect-error deliberately invalid
    expect(() => normalizeAddress({ address: 'a@b.com', name: 5 }, 'x')).toThrow(SmtpMessageError);
    expect(() => normalizeAddress({ address: 'a@b.com<' } as never, 'x')).toThrow(SmtpMessageError);
  });

  it('strips at most one bracket pair and rejects stray brackets', () => {
    expect(stripBrackets('<a@b.com>', 'x')).toBe('a@b.com');
    expect(stripBrackets('a@b.com', 'x')).toBe('a@b.com');
    expect(() => stripBrackets('a<b@c.com', 'x')).toThrow();
    expect(() => stripBrackets('a@b.com\r', 'x')).toThrow();
  });

  it('wraps an addr-spec in angle brackets', () => {
    expect(angleWrap('a@b.com')).toBe('<a@b.com>');
  });
});
