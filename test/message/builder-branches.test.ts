import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { buildMessage } from '../../src/message/builder';
import type { EncodeContext } from '../../src/message/builder';
import { SmtpMessageError } from '../../src/protocol/errors';

const CTX: EncodeContext = { smtpUtf8: false, eightBitMime: false };
const CTX8: EncodeContext = { smtpUtf8: true, eightBitMime: true };

describe('builder branches', () => {
  it('HTML-only message uses text/html', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], html: '<p>hi</p>' },
      CTX,
    );
    expect(m.data).toContain('Content-Type: text/html; charset=UTF-8');
    expect(m.data).not.toContain('multipart');
  });

  it('accepts a base64-encoded attachment and a contentId', () => {
    const payload = Buffer.from('hello world').toString('base64');
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        text: 'body',
        attachments: [
          { filename: 'note.txt', content: payload, encoding: 'base64', contentType: 'text/plain', contentId: 'cid1' },
        ],
      },
      CTX,
    );
    expect(m.data).toContain('Content-ID: <cid1>');
    // The base64 of "hello world" is present in the part.
    expect(m.data).toContain(payload);
  });

  it('encodes a non-ASCII attachment filename', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        text: 'x',
        attachments: [{ filename: 'reçu.pdf', content: Buffer.from('x') }],
      },
      CTX,
    );
    const unfolded = m.data.replace(/\r\n /g, ' ');
    expect(unfolded).toMatch(/filename="=\?UTF-8\?B\?/);
  });

  it('rejects an attachment with a control char in the filename', () => {
    expect(() =>
      buildMessage(
        {
          from: 'a@example.com',
          to: ['b@example.com'],
          text: 'x',
          attachments: [{ filename: 'a\r\nb.txt', content: Buffer.from('x') }],
        },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
    expect(() =>
      buildMessage(
        {
          from: 'a@example.com',
          to: ['b@example.com'],
          text: 'x',
          attachments: [{ filename: '', content: Buffer.from('x') }],
        },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('honors replyTo, a custom messageId, and a custom date', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        replyTo: { name: 'Support', address: 'help@example.com' },
        messageId: '<fixed-id@example.com>',
        date: new Date('2026-03-01T12:00:00Z'),
        text: 'x',
      },
      CTX,
    );
    expect(m.data).toMatch(/^Reply-To: Support <help@example\.com>/m);
    expect(m.messageId).toBe('<fixed-id@example.com>');
    expect(m.data).toMatch(/^Message-ID: <fixed-id@example\.com>/m);
    expect(m.data).toMatch(/^Date: /m);
  });

  it('rejects a malformed custom messageId', () => {
    expect(() =>
      buildMessage(
        { from: 'a@example.com', to: ['b@example.com'], text: 'x', messageId: 'no-brackets' },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('T-DATA-TERMINATOR-ish: a Cc header is emitted and included in the envelope', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        cc: [{ name: 'Carol', address: 'c@example.com' }],
        text: 'x',
      },
      CTX,
    );
    expect(m.data).toMatch(/^Cc: Carol <c@example\.com>/m);
    expect(m.envelopeTo).toContain('c@example.com');
  });

  it('adds a custom extra header (encoded) and rejects a non-string value', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'x', headers: { 'X-Note': 'Réf 12' } },
      CTX,
    );
    expect(m.data).toMatch(/^X-Note: =\?UTF-8\?B\?/m);
    expect(() =>
      buildMessage(
        { from: 'a@example.com', to: ['b@example.com'], text: 'x', headers: { 'X-Bad': 5 as never } },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('quotes a display name containing specials', () => {
    const m = buildMessage(
      { from: { name: 'Doe, John', address: 'a@example.com' }, to: ['b@example.com'], text: 'x' },
      CTX,
    );
    expect(m.data).toMatch(/^From: "Doe, John" <a@example\.com>/m);
  });

  it('emits a long ASCII body line as quoted-printable rather than over 998 octets', () => {
    const longLine = 'x'.repeat(2000);
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: longLine },
      CTX,
    );
    for (const line of m.data.split('\r\n')) {
      expect(Buffer.byteLength(line, 'utf8')).toBeLessThanOrEqual(998);
    }
    expect(m.data).toContain('Content-Transfer-Encoding: quoted-printable');
  });

  it('with 8BITMIME advertised, non-ASCII text is still 7-bit safe (QP)', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'café' },
      CTX8,
    );
    const bytes = Buffer.from(m.data, 'utf8');
    for (const b of bytes) expect(b).toBeLessThanOrEqual(0x7f);
  });

  it('rejects an unknown recipient type', () => {
    expect(() =>
      buildMessage({ from: 'a@example.com', to: [42 as never], text: 'x' }, CTX),
    ).toThrow(SmtpMessageError);
  });
});
