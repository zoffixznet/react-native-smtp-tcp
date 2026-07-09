import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import type { Logger } from '../../src/protocol/types';

const EHLO_PLAIN_PIPE =
  '250-test.local\r\n250-PIPELINING\r\n250-AUTH PLAIN\r\n250 SMTPUTF8\r\n';
const EHLO_NO_PIPE = '250-test.local\r\n250-AUTH PLAIN\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
}

describe('T-INJECTABLE-CORE: the engine drives a fake socket with correct framing', () => {
  it('EHLO, AUTH, MAIL/RCPT/DATA, and CRLF.CRLF termination without any RN import', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_NO_PIPE, once: true },
      { when: /^AUTH PLAIN /m, reply: '235 ok\r\n', once: true },
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 queued\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'u@example.com', pass: 'p' },
    });
    await client.connect();
    await client.sendTransaction({
      from: 'u@example.com',
      to: ['d@example.com'],
      data: 'Subject: x\r\n\r\nbody\r\n',
      sizeBytes: 20,
      smtpUtf8: false,
      eightBitMime: false,
    });
    const wire = sock.writtenText();
    expect(wire).toMatch(/^EHLO \[/m);
    expect(wire).toMatch(/^MAIL FROM:<u@example\.com>/m);
    expect(wire).toMatch(/^RCPT TO:<d@example\.com>/m);
    expect(wire).toMatch(/^DATA\r\n/m);
    expect(wire.endsWith('\r\n.\r\n')).toBe(true);
    client.close();
  });
});

describe('credential redaction in logs (SEC-17)', () => {
  it('T-CREDENTIAL-REDACTION: wire logging shows *** for AUTH payloads and never the secrets', async () => {
    const logs: string[] = [];
    const logger: Logger = { debug: (m) => logs.push(m) };
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_NO_PIPE, once: true },
      { when: /^AUTH PLAIN /m, reply: '235 ok\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'me@example.com', pass: 'hunter2secret' },
      logger,
    });
    await client.connect();
    client.close();
    const all = logs.join('\n');
    // The AUTH command is logged with its argument redacted.
    expect(all).toMatch(/C: AUTH PLAIN \*\*\*/);
    // The plaintext password and its base64 must never appear.
    expect(all).not.toContain('hunter2secret');
    const b64 = Buffer.concat([
      Buffer.from([0]),
      Buffer.from('me@example.com'),
      Buffer.from([0]),
      Buffer.from('hunter2secret'),
    ]).toString('base64');
    expect(all).not.toContain(b64);
  });

  it('redacts XOAUTH2 tokens in logs', async () => {
    const logs: string[] = [];
    const logger: Logger = { debug: (m) => logs.push(m) };
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: '250-test.local\r\n250-AUTH XOAUTH2\r\n250 OK\r\n', once: true },
      { when: /^AUTH XOAUTH2 /m, reply: '235 ok\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'me@example.com', type: 'oauth2', accessToken: 'ya29.SECRETTOKEN' },
      logger,
    });
    await client.connect();
    client.close();
    const all = logs.join('\n');
    expect(all).not.toContain('ya29.SECRETTOKEN');
    expect(all).toMatch(/C: AUTH XOAUTH2 \*\*\*/);
  });
});

describe('pipelining advertisement (COR-15)', () => {
  it('T-PIPELINING-NOT-ADVERTISED: capabilities reflect no PIPELINING', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [{ when: /^EHLO /m, reply: EHLO_NO_PIPE, once: true }]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    const caps = await client.connect();
    expect(caps.pipelining).toBe(false);
    client.close();
  });

  it('parses PIPELINING when advertised', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [{ when: /^EHLO /m, reply: EHLO_PLAIN_PIPE, once: true }]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    const caps = await client.connect();
    expect(caps.pipelining).toBe(true);
    client.close();
  });
});
