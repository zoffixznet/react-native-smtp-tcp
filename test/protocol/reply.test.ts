import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { ReplyReader } from '../../src/protocol/reply-reader';
import { ReplyParser } from '../../src/protocol/reply-parser';
import { DEFAULT_CAPS } from '../../src/protocol/caps';
import type { Caps, SmtpReply } from '../../src/protocol/types';
import { SmtpProtocolError } from '../../src/protocol/errors';

/** Feed a raw string through reader+parser and return completed replies. */
function parseAll(input: string, caps: Caps = DEFAULT_CAPS): SmtpReply[] {
  const reader = new ReplyReader(caps);
  const parser = new ReplyParser();
  const replies: SmtpReply[] = [];
  const lines = reader.push(new Uint8Array(Buffer.from(input, 'utf8')));
  for (const line of lines) {
    const step = parser.push(line);
    if (step.done) {
      reader.finishReply();
      replies.push(step.reply);
    }
  }
  return replies;
}

describe('reply parsing', () => {
  it('T-MULTILINE-OK: a 3-line 250 reply completes only at the final line', () => {
    const replies = parseAll('250-first\r\n250-second\r\n250 final\r\n');
    expect(replies).toHaveLength(1);
    expect(replies[0].code).toBe(250);
    expect(replies[0].lines).toEqual(['first', 'second', 'final']);
  });

  it('completes only at code+SP, not at code+-', () => {
    const parser = new ReplyParser();
    expect(parser.push('250-a').done).toBe(false);
    expect(parser.push('250-b').done).toBe(false);
    const step = parser.push('250 c');
    expect(step.done).toBe(true);
  });

  it('T-MULTILINE-MISMATCH: differing continuation code is a protocol violation', () => {
    expect(() => parseAll('250-hello\r\n500 boom\r\n')).toThrow(SmtpProtocolError);
  });

  it('T-MALFORMED-CODES: malformed codes are rejected, not coerced', () => {
    for (const bad of ['2xx ok\r\n', '25 ok\r\n', '2500 ok\r\n', '-99 ok\r\n', '   ok\r\n']) {
      expect(() => parseAll(bad), bad).toThrow(SmtpProtocolError);
    }
  });

  it('rejects a leading digit outside 1..5', () => {
    expect(() => parseAll('650 nope\r\n')).toThrow(SmtpProtocolError);
    expect(() => parseAll('099 nope\r\n')).toThrow(SmtpProtocolError);
  });

  it('T-ENHANCED-CODES: parses enhanced codes when present and matching the class', () => {
    const [r1] = parseAll('250 2.1.5 ok\r\n');
    expect(r1.enhanced).toEqual({ class: 2, subject: 1, detail: 5 });

    const [r2] = parseAll('250 ok\r\n');
    expect(r2.enhanced).toBeUndefined();

    // Enhanced class mismatched with the basic code is ignored.
    const [r3] = parseAll('250 9.9.9 weird\r\n');
    expect(r3.enhanced).toBeUndefined();
    expect(r3.code).toBe(250);
  });

  it('T-TRAILING-WS: tolerates trailing whitespace while keeping the code', () => {
    const [r] = parseAll('250   ok   \r\n');
    expect(r.code).toBe(250);
    expect(r.lines[0]).toContain('ok');
  });

  it('accepts a bare 3-digit code line as final', () => {
    const [r] = parseAll('220\r\n');
    expect(r.code).toBe(220);
  });
});

describe('reply reader DoS caps', () => {
  it('T-GIANT-LINE: aborts at the per-line cap without buffering unbounded', () => {
    const caps: Caps = { ...DEFAULT_CAPS, maxLineBytes: 1024 };
    const reader = new ReplyReader(caps);
    const chunk = Buffer.concat([Buffer.from('250 '), Buffer.alloc(5000, 0x61)]); // no CRLF
    expect(() => reader.push(new Uint8Array(chunk))).toThrow(SmtpProtocolError);
  });

  it('T-NEVER-FINAL: aborts on the continuation-line cap for an endless 250-', () => {
    const caps: Caps = { ...DEFAULT_CAPS, maxContinuationLines: 10, maxReplyBytes: 1 << 20 };
    const reader = new ReplyReader(caps);
    const parser = new ReplyParser();
    let threw = false;
    try {
      for (let i = 0; i < 1000; i++) {
        const lines = reader.push(new Uint8Array(Buffer.from('250-a\r\n')));
        for (const line of lines) parser.push(line);
      }
    } catch (err) {
      threw = err instanceof SmtpProtocolError;
    }
    expect(threw).toBe(true);
  });

  it('aborts on the total reply byte cap', () => {
    const caps: Caps = { ...DEFAULT_CAPS, maxReplyBytes: 100, maxContinuationLines: 10000 };
    const reader = new ReplyReader(caps);
    let threw = false;
    try {
      for (let i = 0; i < 1000; i++) {
        reader.push(new Uint8Array(Buffer.from('250-abcdefghij\r\n')));
      }
    } catch (err) {
      threw = err instanceof SmtpProtocolError;
    }
    expect(threw).toBe(true);
  });

  it('reassembles a reply delivered one byte at a time', () => {
    const reader = new ReplyReader(DEFAULT_CAPS);
    const parser = new ReplyParser();
    const input = Buffer.from('250 ok\r\n');
    const replies: SmtpReply[] = [];
    for (const byte of input) {
      const lines = reader.push(new Uint8Array([byte]));
      for (const line of lines) {
        const step = parser.push(line);
        if (step.done) replies.push(step.reply);
      }
    }
    expect(replies).toHaveLength(1);
    expect(replies[0].code).toBe(250);
  });

  it('reports buffered bytes for the STARTTLS drain check', () => {
    const reader = new ReplyReader(DEFAULT_CAPS);
    // 220 line plus an injected extra line in one segment.
    reader.push(new Uint8Array(Buffer.from('220 ok\r\n250 injected\r\n')));
    // After reading both lines, nothing should remain buffered; but if we only
    // consume one line's worth by pushing partial data, residual is reported.
    const reader2 = new ReplyReader(DEFAULT_CAPS);
    const lines = reader2.push(new Uint8Array(Buffer.from('220 ok\r\n250 extra')));
    expect(lines).toEqual(['220 ok']);
    expect(reader2.hasBufferedBytes()).toBe(true);
    expect(reader2.bufferedByteCount()).toBe('250 extra'.length);
  });

  it('T-REDOS: parses a pathological reply line in linear time', () => {
    const caps: Caps = { ...DEFAULT_CAPS, maxLineBytes: 200000, maxReplyBytes: 300000 };
    const reader = new ReplyReader(caps);
    const parser = new ReplyParser();
    const line = '250 ' + ' '.repeat(50000) + '-'.repeat(50000) + '\r\n';
    const start = Date.now();
    const lines = reader.push(new Uint8Array(Buffer.from(line, 'utf8')));
    for (const l of lines) parser.push(l);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(200);
  });
});
