import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { SmtpProtocolError } from '../../src/protocol/errors';

const EHLO = '250-test.local\r\n250-SIZE 100000\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket, ehlo = EHLO): ReturnType<typeof driveFake> {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  return driveFake(sock, [{ when: /^EHLO /m, reply: ehlo, once: true }]);
}

async function connectImplicit(sock: FakeSocket) {
  const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
  // Mark the channel validated (implicit path sets encrypted via secureConnect;
  // verifyTlsChannel default accepts, setting validated).
  await client.connect();
  return client;
}

describe('transaction (COR-6)', () => {
  it('T-TRANSACTION-ORDER: MAIL 250 -> RCPT 250 -> DATA 354 -> body -> 250', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 2.1.0 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 2.1.5 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 Go ahead\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 2.0.0 Queued\r\n', once: true },
    ]);
    const client = await connectImplicit(sock);
    const res = await client.sendTransaction({
      from: 'me@example.com',
      to: ['you@example.com'],
      data: 'Subject: hi\r\n\r\nbody line\r\n',
      sizeBytes: 30,
      smtpUtf8: false,
      eightBitMime: false,
    });
    expect(res.accepted).toEqual(['you@example.com']);
    // Wire order and framing.
    const wire = sock.writtenText();
    expect(wire).toMatch(/MAIL FROM:<me@example\.com> SIZE=30/);
    expect(wire).toMatch(/RCPT TO:<you@example\.com>/);
    expect(wire).toMatch(/DATA\r\n/);
    expect(wire.endsWith('\r\n.\r\n')).toBe(true);
    client.close();
  });

  it('T-TRANSACTION-ORDER: a 550 RCPT fails the whole send cleanly (with RSET)', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '550 5.1.1 No such user\r\n', once: true },
      { when: /^RSET/m, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connectImplicit(sock);
    await expect(
      client.sendTransaction({
        from: 'me@example.com',
        to: ['ghost@example.com'],
        data: 'Subject: x\r\n\r\nx\r\n',
        sizeBytes: 20,
        smtpUtf8: false,
        eightBitMime: false,
      }),
    ).rejects.toBeInstanceOf(SmtpProtocolError);
    expect(sock.writtenText()).toMatch(/^RSET/m);
    client.close();
  });

  it('T-ANGLE-BRACKETS: addresses are wrapped once, never double-wrapped', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connectImplicit(sock);
    await client.sendTransaction({
      from: 'me@example.com',
      to: ['you@example.com'],
      data: 'Subject: x\r\n\r\nx\r\n',
      sizeBytes: 20,
      smtpUtf8: false,
      eightBitMime: false,
    });
    const wire = sock.writtenText();
    expect(wire).toContain('MAIL FROM:<me@example.com>');
    expect(wire).not.toContain('<<');
    expect(wire).not.toContain('>>');
    client.close();
  });

  it('T-SIZE-LIMITS: refuses locally when the message exceeds the advertised SIZE', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 SIZE 100\r\n');
    const client = await connectImplicit(sock);
    await expect(
      client.sendTransaction({
        from: 'me@example.com',
        to: ['you@example.com'],
        data: 'x'.repeat(500),
        sizeBytes: 500,
        smtpUtf8: false,
        eightBitMime: false,
      }),
    ).rejects.toBeInstanceOf(SmtpProtocolError);
    // No MAIL FROM was sent because we refused before upload.
    expect(sock.writtenText()).not.toMatch(/^MAIL FROM/m);
    client.close();
  });

  it('dot-stuffs a lone dot in the body so DATA is not terminated early', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connectImplicit(sock);
    await client.sendTransaction({
      from: 'me@example.com',
      to: ['you@example.com'],
      // A body line that is exactly "." must be sent as "..".
      data: 'Subject: x\r\n\r\n.\r\n',
      sizeBytes: 20,
      smtpUtf8: false,
      eightBitMime: false,
    });
    const wire = sock.writtenText();
    // The stuffed dot: "\r\n..\r\n" appears, and the real terminator is the last.
    expect(wire).toContain('\r\n..\r\n');
    expect(wire.endsWith('\r\n.\r\n')).toBe(true);
    client.close();
  });
});

describe('EHLO/HELO fallback (COR-2)', () => {
  it('T-HELO-FALLBACK: falls back to HELO on a 502, not on a 4xx', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    driveFake(sock, [
      { when: /^EHLO /m, reply: '502 command not implemented\r\n', once: true },
      { when: /^HELO /m, reply: '250 test.local\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    const caps = await client.connect();
    expect(caps.startTls).toBe(false);
    expect(sock.writtenText()).toMatch(/^HELO /m);
    client.close();
  });

  it('does not fall back to HELO on a 4xx transient', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    driveFake(sock, [{ when: /^EHLO /m, reply: '421 try later\r\n', once: true }]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpProtocolError);
    expect(sock.writtenText()).not.toMatch(/^HELO /m);
  });
});
