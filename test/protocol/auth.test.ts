import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { SmtpAuthError, SmtpSecurityError } from '../../src/protocol/errors';

const EHLO_AUTH = (mechs: string) =>
  `250-test.local\r\n250-AUTH ${mechs}\r\n250 SMTPUTF8\r\n`;

/** Start an implicit-TLS connection: fire secureConnect then the greeting. */
function startImplicit(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
}

describe('AUTH gating and mechanisms', () => {
  it('T-AUTH-CLEARTEXT-GATE: never writes AUTH before TLS on a cleartext link', async () => {
    // A STARTTLS account where STARTTLS is stripped must error before AUTH.
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireConnect();
      sock.serverSend('220 test.local ESMTP\r\n');
    });
    driveFake(sock, [
      { when: /^EHLO /m, reply: '250-test.local\r\n250 AUTH PLAIN\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'starttls',
      auth: { user: 'u@example.com', pass: 'pw' },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    expect(sock.writtenText()).not.toMatch(/^AUTH /mi);
  });

  it('T-AUTH-MECH-NEGOTIATION: picks the strongest and never sends an unadvertised mech', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_AUTH('XOAUTH2 PLAIN LOGIN CRAM-MD5'), once: true },
      { when: /^AUTH XOAUTH2 /m, reply: '235 2.7.0 Authenticated\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'me@example.com', type: 'oauth2', accessToken: 'TOK' },
    });
    await client.connect();
    const wire = sock.writtenText();
    expect(wire).toMatch(/^AUTH XOAUTH2 /m);
    expect(wire).not.toMatch(/AUTH PLAIN/);
    expect(wire).not.toMatch(/CRAM-MD5/);
    client.close();
  });

  it('refuses when no acceptable mechanism is advertised', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [{ when: /^EHLO /m, reply: EHLO_AUTH('CRAM-MD5 SCRAM-SHA-256'), once: true }]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'u@example.com', pass: 'pw' },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpAuthError);
  });

  it('T-LOGIN-SEQUENCE: drives the AUTH LOGIN 334 exchange', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_AUTH('LOGIN'), once: true },
      { when: /^AUTH LOGIN/m, reply: `334 ${Buffer.from('Username:').toString('base64')}\r\n`, once: true },
      {
        when: new RegExp(`^${Buffer.from('alice').toString('base64')}`, 'm'),
        reply: `334 ${Buffer.from('Password:').toString('base64')}\r\n`,
        once: true,
      },
      {
        when: new RegExp(`^${Buffer.from('secret').toString('base64')}`, 'm'),
        reply: '235 2.7.0 ok\r\n',
        once: true,
      },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'alice', pass: 'secret' },
    });
    await client.connect();
    const lines = sock.writtenText().split('\r\n');
    expect(lines).toContain(Buffer.from('alice').toString('base64'));
    expect(lines).toContain(Buffer.from('secret').toString('base64'));
    client.close();
  });

  it('T-XOAUTH2-ERROR: on a 334 error challenge, sends an empty line then surfaces 535', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_AUTH('XOAUTH2'), once: true },
      { when: /^AUTH XOAUTH2 /m, reply: '334 eyJzdGF0dXMiOiI0MDEifQ==\r\n', once: true },
      // After the empty line, the final failure.
      { when: /^\r\n/, reply: '535 5.7.8 authentication failed\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'me@example.com', type: 'oauth2', accessToken: 'TOK' },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpAuthError);
    client.close();
  });
});

describe('auth failure hygiene (SEC-19)', () => {
  async function runAuthWith(code: string): Promise<Error> {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO_AUTH('PLAIN'), once: true },
      { when: /^AUTH PLAIN /m, reply: `${code}\r\n`, once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'me@example.com', pass: 'topsecretpassword' },
    });
    try {
      await client.connect();
      throw new Error('expected auth to fail');
    } catch (err) {
      client.close();
      return err as Error;
    }
  }

  it('T-FAILURE-CODES: 535 is permanent and generic', async () => {
    const err = await runAuthWith('535 5.7.8 Username and Password not accepted');
    expect(err).toBeInstanceOf(SmtpAuthError);
    expect((err as SmtpAuthError).transient).toBe(false);
    expect(err.message).toBe('authentication failed');
  });

  it('T-FAILURE-CODES: 454 is transient, 432 is a password transition', async () => {
    const e454 = await runAuthWith('454 4.7.0 Temporary authentication failure');
    expect((e454 as SmtpAuthError).transient).toBe(true);
    const e432 = await runAuthWith('432 4.7.12 A password transition is needed');
    expect((e432 as SmtpAuthError).transient).toBe(false);
    expect(e432.message).toMatch(/transition/);
  });

  it('T-EXCEPTION-HYGIENE: the error carries no credential material', async () => {
    const err = await runAuthWith('535 5.7.8 nope');
    const serialized = `${err.message}\n${err.stack ?? ''}`;
    expect(serialized).not.toContain('topsecretpassword');
    expect(serialized).not.toContain('me@example.com');
    // No base64 AUTH payload leaks either.
    expect(serialized).not.toMatch(/AH[A-Za-z0-9+/=]{6,}/);
  });
});
