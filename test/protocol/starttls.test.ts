import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { SmtpSecurityError } from '../../src/protocol/errors';

const EHLO_WITH_STARTTLS =
  '250-test.local\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SMTPUTF8\r\n';
const EHLO_IN_TLS =
  '250-test.local\r\n250-AUTH PLAIN LOGIN XOAUTH2\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n';

/** Fire the plaintext connect and greeting after connect() starts listening. */
function startPlain(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
}

describe('STARTTLS security invariants', () => {
  it('T-STARTTLS-INJECTION: aborts when extra bytes follow the 220 in one segment', async () => {
    const sock = new FakeSocket();
    startPlain(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_WITH_STARTTLS, once: true },
      {
        when: /^STARTTLS/m,
        // 220 plus an injected line in the SAME segment (CVE-2011-0411 class).
        reply: '220 2.0.0 Ready to start TLS\r\n250 injected-should-be-ignored\r\n',
        once: true,
      },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    // The socket must not have been upgraded to TLS with residual bytes present.
    expect(sock.upgraded).toBeNull();
  });

  it('T-PRETLS-GREETING-INJECTION: consumes exactly the STARTTLS line, hands a clean stream', async () => {
    const sock = new FakeSocket();
    // Greeting arrives, EHLO, STARTTLS returns a clean single 220 line, no junk.
    startPlain(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_WITH_STARTTLS, once: true },
      { when: /^STARTTLS/m, reply: '220 Go ahead\r\n', once: true },
      { when: /^EHLO /m, reply: EHLO_IN_TLS, once: true },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    const caps = await client.connect();
    // Upgrade happened cleanly and the in-TLS capabilities are used.
    expect(sock.upgraded).not.toBeNull();
    expect(caps.authMechanisms).toContain('XOAUTH2');
    client.close();
  });

  it('T-EHLO-DISCARD: acts only on the in-TLS capability list', async () => {
    const sock = new FakeSocket();
    startPlain(sock);
    driveFake(sock, [
      // Pre-TLS advertises a bogus capability set.
      {
        when: /^EHLO /m,
        reply: '250-test.local\r\n250-STARTTLS\r\n250 X-PLAINTEXT-ONLY\r\n',
        once: true,
      },
      { when: /^STARTTLS/m, reply: '220 Go ahead\r\n', once: true },
      // In-TLS advertises the real set.
      { when: /^EHLO /m, reply: EHLO_IN_TLS, once: true },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    const caps = await client.connect();
    expect(caps.raw.has('X-PLAINTEXT-ONLY')).toBe(false);
    expect(caps.authMechanisms).toContain('XOAUTH2');
    expect(caps.eightBitMime).toBe(true);
    client.close();
  });

  it('T-STARTTLS-STRIP: aborts when STARTTLS is not advertised', async () => {
    const sock = new FakeSocket();
    startPlain(sock);
    driveFake(sock, [
      // STARTTLS removed / garbled.
      { when: /^EHLO /m, reply: '250-test.local\r\n250-XXXXXXXX\r\n250 AUTH PLAIN\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    // No AUTH / MAIL / credentials were ever written in cleartext.
    expect(sock.writtenText()).not.toMatch(/^AUTH /m);
    expect(sock.writtenText()).not.toMatch(/^MAIL /m);
  });

  it('T-STARTTLS-454: aborts when STARTTLS is refused with 454', async () => {
    const sock = new FakeSocket();
    startPlain(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_WITH_STARTTLS, once: true },
      { when: /^STARTTLS/m, reply: '454 4.7.0 TLS not available\r\n', once: true },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    expect(sock.upgraded).toBeNull();
    expect(sock.writtenText()).not.toMatch(/^AUTH /m);
  });

  it('detaches the plaintext data listener before the TLS wrap', async () => {
    const sock = new FakeSocket();
    startPlain(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_WITH_STARTTLS, once: true },
      { when: /^STARTTLS/m, reply: '220 Go ahead\r\n', once: true },
      { when: /^EHLO /m, reply: EHLO_IN_TLS, once: true },
    ]);
    const client = makeClient(sock, { secure: 'starttls' });
    await client.connect();
    // After the upgrade the pre-TLS socket has no data listeners left.
    expect(sock.listenerCount('data')).toBe(0);
    client.close();
  });
});
