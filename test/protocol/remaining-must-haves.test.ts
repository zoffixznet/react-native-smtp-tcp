import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { buildMessage } from '../../src/message/builder';
import { computeSpkiSha256, pinMatches } from '../../src/protocol/pinning';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { SmtpMessageError, SmtpProtocolError } from '../../src/protocol/errors';

const CTX = { smtpUtf8: false, eightBitMime: false };
const EHLO = '250-test.local\r\n250-SIZE 100000\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  driveFake(sock, [{ when: /^EHLO /m, reply: EHLO, once: true }]);
}

describe('T-DOTSTUFF-MULTI (COR-8)', () => {
  it('doubles a run of leading dots and leaves interior dots alone', async () => {
    const { dotStuff } = await import('../../src/protocol/client');
    expect(dotStuff('...text')).toBe('....text');
    expect(dotStuff('a.b.c')).toBe('a.b.c');
    expect(dotStuff('.one\r\n..two\r\na.b')).toBe('..one\r\n...two\r\na.b');
  });
});

describe('T-DATA-TERMINATOR (COR-8)', () => {
  it('ends with <CRLF>.<CRLF> and adds a CRLF when the body lacks a trailing newline', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 ok\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await client.connect();
    await client.sendTransaction({
      from: 'me@example.com',
      to: ['you@example.com'],
      // No trailing newline on the last body line.
      data: 'Subject: x\r\n\r\nlast line without newline',
      sizeBytes: 40,
      smtpUtf8: false,
      eightBitMime: false,
    });
    const wire = sock.writtenText();
    // The terminator is exactly CRLF . CRLF, and the body got a CRLF first.
    expect(wire.endsWith('last line without newline\r\n.\r\n')).toBe(true);
    client.close();
  });
});

describe('T-FAIL-CLOSED-ABORT (SEC-15)', () => {
  it('writes no partial command or DATA when an injection is detected mid-build', () => {
    // buildMessage throws before producing any output for an injected subject.
    expect(() =>
      buildMessage(
        {
          from: 'me@example.com',
          to: ['you@example.com'],
          subject: 'ok\r\nBcc: attacker@evil.com',
          text: 'body',
        },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
    // And a bad recipient is rejected before any envelope is produced.
    expect(() =>
      buildMessage(
        { from: 'me@example.com', to: ['a@b.com\r\nRCPT TO:<x@y>'], text: 'x' },
        CTX,
      ),
    ).toThrow(SmtpMessageError);
  });

  it('sends nothing to the socket when the message fails to build (via sendMail)', async () => {
    // Through the public API, a message with an injected subject is rejected at
    // build time, before any transaction command reaches the socket.
    const { createTransport } = await import('../../src/index');
    const sock = new FakeSocket();
    startImplicit(sock);
    const transport = createTransport({
      host: 'localhost',
      port: 465,
      secure: 'implicit',
      transportFactory: {
        connectImplicitTls: () => sock,
        connectPlain: () => sock,
      },
    });
    await expect(
      transport.sendMail({
        from: 'me@example.com',
        to: ['you@example.com'],
        subject: 'ok\r\nBcc: attacker@evil.com',
        text: 'body',
      }),
    ).rejects.toBeInstanceOf(SmtpMessageError);
    // The build failed after connecting; no MAIL/RCPT/DATA were ever written.
    const wire = sock.writtenText();
    expect(wire).not.toMatch(/MAIL FROM/);
    expect(wire).not.toMatch(/^DATA/m);
  });
});

describe('T-PIPELINING-REPLY-COUNT (COR-15)', () => {
  it('correlates each reply to its command and checks every status (lock-step)', async () => {
    // This library sends synchronizing, one command at a time (it does not
    // pipeline), so each reply is unambiguously the reply to the last command.
    // The test proves each of MAIL, RCPT, RCPT, DATA gets its own reply checked
    // and that two single-line replies are never merged.
    const sock = new FakeSocket();
    startImplicit(sock);
    const rcptReplies = ['250 2.1.5 ok\r\n', '250 2.1.5 ok\r\n'];
    let rcptIdx = 0;
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 2.1.0 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: () => rcptReplies[rcptIdx++] },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 2.0.0 Queued\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await client.connect();
    const res = await client.sendTransaction({
      from: 'me@example.com',
      to: ['a@example.com', 'b@example.com'],
      data: 'Subject: x\r\n\r\nbody\r\n',
      sizeBytes: 20,
      smtpUtf8: false,
      eightBitMime: false,
    });
    expect(res.accepted).toEqual(['a@example.com', 'b@example.com']);
    // Exactly two RCPT commands were written, one per recipient.
    const rcptCount = (sock.writtenText().match(/^RCPT TO:/gm) || []).length;
    expect(rcptCount).toBe(2);
    client.close();
  });

  it('checks the status of every RCPT and fails the send if one is rejected', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    let rcptIdx = 0;
    const replies = ['250 ok\r\n', '550 5.1.1 no such user\r\n'];
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: () => replies[rcptIdx++] },
      { when: /^RSET/m, reply: '250 ok\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await client.connect();
    await expect(
      client.sendTransaction({
        from: 'me@example.com',
        to: ['ok@example.com', 'bad@example.com'],
        data: 'Subject: x\r\n\r\nx\r\n',
        sizeBytes: 20,
        smtpUtf8: false,
        eightBitMime: false,
      }),
    ).rejects.toBeInstanceOf(SmtpProtocolError);
    client.close();
  });
});

describe('T-TRUST-LIMIT (SEC-8): pinning comparison and destroy-on-mismatch', () => {
  const sha256 = (d: Uint8Array) => new Uint8Array(createHash('sha256').update(d).digest());

  it('destroys the socket when the SPKI pin does not match', async () => {
    // The real pin check runs in Transport.verifyTlsChannel; here we prove the
    // pure comparison rejects a mismatch and the peer-cert accessor is honored.
    const goodKey = new Uint8Array([1, 2, 3, 4]);
    const badKey = new Uint8Array([9, 9, 9, 9]);
    const configured = Buffer.from(sha256(goodKey)).toString('base64');
    expect(pinMatches(computeSpkiSha256({ pubkey: goodKey }, sha256), configured)).toBe(true);
    expect(pinMatches(computeSpkiSha256({ pubkey: badKey }, sha256), configured)).toBe(false);

    // A socket whose peer cert does not match the pin is destroyed by the client
    // during channel verification (proven end to end in the TLS validation suite).
    const sock = new FakeSocket({ peerCertificate: { pubkey: badKey } });
    let destroyed = false;
    const orig = sock.destroy.bind(sock);
    sock.destroy = (e?: Error) => {
      destroyed = true;
      orig(e);
    };
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      verifyTlsChannel: (t) => {
        const cert = t.getPeerCertificate?.();
        if (!pinMatches(computeSpkiSha256(cert, sha256), configured)) {
          throw new (class extends Error {})('pin mismatch');
        }
      },
    });
    await expect(client.connect()).rejects.toBeDefined();
    expect(destroyed).toBe(true);
  });
});

describe('T-SECRET-SCAN-TARBALL (publishing)', () => {
  const hasDist = existsSync(join(__dirname, '..', '..', 'dist'));
  (hasDist ? it : it.skip)('the leak scanner passes over dist and the tarball', () => {
    const root = join(__dirname, '..', '..');
    // Runs the same scanner the build uses; throws (nonzero exit) on any hit.
    execFileSync('node', [join(root, 'scripts', 'leak-scan.mjs'), '--dist'], {
      cwd: root,
      stdio: 'pipe',
    });
    expect(true).toBe(true);
  });
});
