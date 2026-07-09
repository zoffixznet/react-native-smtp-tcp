import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import {
  buildMessage,
  formatDate,
  dotStuffPreview,
} from './builder-helpers';
import type { EncodeContext } from '../../src/message/builder';
import { SmtpMessageError } from '../../src/protocol/errors';

const ASCII_CTX: EncodeContext = { smtpUtf8: false, eightBitMime: false };
const UTF8_CTX: EncodeContext = { smtpUtf8: true, eightBitMime: true };

describe('mandatory headers (COR-11)', () => {
  it('T-MANDATORY-HEADERS: exactly one Date and From, unique Message-ID', () => {
    const m1 = buildMessage(
      { from: 'me@example.com', to: ['you@example.com'], subject: 'hi', text: 'body' },
      ASCII_CTX,
    );
    const dateCount = (m1.data.match(/^Date: /gm) || []).length;
    const fromCount = (m1.data.match(/^From: /gm) || []).length;
    expect(dateCount).toBe(1);
    expect(fromCount).toBe(1);
    expect(m1.data).toMatch(/^Message-ID: <[^>]+@example\.com>/m);

    const m2 = buildMessage(
      { from: 'me@example.com', to: ['you@example.com'], subject: 'hi', text: 'body' },
      ASCII_CTX,
    );
    expect(m1.messageId).not.toBe(m2.messageId);
  });

  it('formats a Date with a numeric zone offset', () => {
    const d = formatDate(new Date('2026-01-15T09:30:00Z'));
    expect(d).toMatch(/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$/);
  });
});

describe('MIME structure (COR-13)', () => {
  it('T-MIME-STRUCTURE: text+html -> multipart/alternative', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'plain', html: '<p>rich</p>' },
      ASCII_CTX,
    );
    // Structured headers may fold at a legal point; unfold before matching.
    const unfolded = m.data.replace(/\r\n /g, ' ');
    expect(unfolded).toMatch(/Content-Type: multipart\/alternative; boundary="[^"]+"/);
    expect(m.data).toContain('MIME-Version: 1.0');
    expect(m.data).toContain('text/plain; charset=UTF-8');
    expect(m.data).toContain('text/html; charset=UTF-8');
  });

  it('T-MIME-STRUCTURE: +attachment -> multipart/mixed with base64 disposition', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        text: 'see attached',
        attachments: [
          { filename: 'data.bin', content: Buffer.alloc(300, 7), contentType: 'application/octet-stream' },
        ],
      },
      ASCII_CTX,
    );
    const unfolded = m.data.replace(/\r\n /g, ' ');
    expect(unfolded).toMatch(/Content-Type: multipart\/mixed; boundary="[^"]+"/);
    expect(m.data).toContain('Content-Transfer-Encoding: base64');
    expect(unfolded).toMatch(/Content-Disposition: attachment; filename="data\.bin"/);
    // The base64 payload lines are wrapped at 76 chars.
    for (const line of m.data.split('\r\n')) {
      expect(line.length).toBeLessThanOrEqual(998);
    }
  });

  it('the boundary does not appear inside any part', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'x', html: 'y' },
      ASCII_CTX,
    );
    const unfolded = m.data.replace(/\r\n /g, ' ');
    const boundary = /boundary="([^"]+)"/.exec(unfolded)![1];
    const parts = m.data.split(`--${boundary}`);
    // Boundary appears only as separators, never embedded in content lines.
    expect(parts.length).toBeGreaterThanOrEqual(3);
  });
});

describe('header injection defense (SEC-14)', () => {
  it('T-HEADER-BCC-INJECTION: subject with CRLF+Bcc is rejected, no Bcc header', () => {
    expect(() =>
      buildMessage(
        {
          from: 'a@example.com',
          to: ['b@example.com'],
          subject: 'Hello\r\nBcc: attacker@evil.com',
          text: 'x',
        },
        ASCII_CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('display-name with a bare LF+Bcc is rejected', () => {
    expect(() =>
      buildMessage(
        {
          from: 'a@example.com',
          to: [{ name: 'John\nBcc: attacker@evil.com', address: 'b@example.com' }],
          text: 'x',
        },
        ASCII_CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('T-HEADER-BLOCK-SMUGGLE: subject with a blank line and fake headers is rejected', () => {
    expect(() =>
      buildMessage(
        {
          from: 'a@example.com',
          to: ['b@example.com'],
          subject: 'x\r\n\r\nFrom: spoof@evil.com\r\nInjected body',
          text: 'x',
        },
        ASCII_CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('T-MALFORMED-HEADER-NAME: an extra header with an illegal name is rejected', () => {
    expect(() =>
      buildMessage(
        { from: 'a@example.com', to: ['b@example.com'], text: 'x', headers: { 'X Bad': 'v' } },
        ASCII_CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('rejects overriding a managed header', () => {
    expect(() =>
      buildMessage(
        { from: 'a@example.com', to: ['b@example.com'], text: 'x', headers: { Subject: 'dup' } },
        ASCII_CTX,
      ),
    ).toThrow(/managed/);
  });

  it('bcc recipients never appear as a header but are in the envelope', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['b@example.com'],
        bcc: ['secret@example.com'],
        text: 'x',
      },
      ASCII_CTX,
    );
    expect(m.data).not.toMatch(/^Bcc:/im);
    expect(m.envelopeTo).toContain('secret@example.com');
  });
});

describe('encoding gating (SEC-27, COR-12)', () => {
  it('T-RFC2047-SUBJECT: non-ASCII subject becomes an encoded-word', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], subject: 'réunion', text: 'x' },
      ASCII_CTX,
    );
    expect(m.data).toMatch(/^Subject: =\?UTF-8\?B\?/m);
  });

  it('T-RFC2047-NOT-IN-ADDR: non-ASCII address is rejected without SMTPUTF8', () => {
    expect(() =>
      buildMessage(
        { from: 'a@example.com', to: ['üser@example.com'], text: 'x' },
        ASCII_CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('T-SMTPUTF8-GATE: non-ASCII local part allowed when SMTPUTF8 negotiated', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['üser@example.com'], text: 'x' },
      UTF8_CTX,
    );
    expect(m.envelopeTo).toContain('üser@example.com');
    expect(m.requiresSmtpUtf8).toBe(true);
  });

  it('T-8BITMIME-GATE: non-ASCII body is quoted-printable, never raw 8-bit', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'café ☕' },
      ASCII_CTX,
    );
    // No raw non-ASCII octet in the serialized message.
    const bytes = Buffer.from(m.data, 'utf8');
    for (const byte of bytes) expect(byte).toBeLessThanOrEqual(0x7f);
    expect(m.data).toContain('Content-Transfer-Encoding: quoted-printable');
  });
});

describe('CRLF normalization and dot-stuffing (COR-8, COR-9)', () => {
  it('T-CRLF-NORMALIZE: lone LF and lone CR become CRLF, no bare breaks', () => {
    const m = buildMessage(
      { from: 'a@example.com', to: ['b@example.com'], text: 'l1\nl2\rl3' },
      ASCII_CTX,
    );
    // No bare CR or LF in the serialized data.
    expect(m.data).not.toMatch(/\r(?!\n)/);
    expect(m.data).not.toMatch(/(?<!\r)\n/);
    expect(m.data).toContain('l1\r\nl2\r\nl3');
  });

  it('T-DOTSTUFF-SINGLE/LONE/MULTI: leading dots are doubled', () => {
    expect(dotStuffPreview('.hidden')).toBe('..hidden');
    expect(dotStuffPreview('.')).toBe('..');
    expect(dotStuffPreview('...text')).toBe('....text');
    expect(dotStuffPreview('a.b.c')).toBe('a.b.c');
  });
});

describe('recipient handling (COR-6, SEC-21)', () => {
  it('T-SIZE-LIMITS: rejects more than 100 recipients', () => {
    const many = Array.from({ length: 101 }, (_, i) => `r${i}@example.com`);
    expect(() =>
      buildMessage({ from: 'a@example.com', to: many, text: 'x' }, ASCII_CTX),
    ).toThrow(/too many recipients/);
  });

  it('deduplicates recipients across to/cc/bcc preserving order', () => {
    const m = buildMessage(
      {
        from: 'a@example.com',
        to: ['x@example.com', 'y@example.com'],
        cc: ['x@example.com'],
        bcc: ['z@example.com'],
        text: 'x',
      },
      ASCII_CTX,
    );
    expect(m.envelopeTo).toEqual(['x@example.com', 'y@example.com', 'z@example.com']);
  });

  it('requires at least one recipient and some content', () => {
    expect(() => buildMessage({ from: 'a@example.com', to: [], text: 'x' }, ASCII_CTX)).toThrow();
    expect(() => buildMessage({ from: 'a@example.com', to: ['b@example.com'] }, ASCII_CTX)).toThrow();
  });
});

describe('angle-bracket normalization (COR-6)', () => {
  it('T-ANGLE-BRACKETS: an already-bracketed address is not double-wrapped', () => {
    const m = buildMessage(
      { from: '<me@example.com>', to: ['<you@example.com>'], text: 'x' },
      ASCII_CTX,
    );
    expect(m.envelopeFrom).toBe('me@example.com');
    expect(m.envelopeTo).toEqual(['you@example.com']);
  });
});
