import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { tlsVersionRank } from '../../src/protocol/client';
import { SmtpSecurityError } from '../../src/protocol/errors';

const EHLO = '250-test.local\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  driveFake(sock, [{ when: /^EHLO /m, reply: EHLO, once: true }]);
}

describe('post-handshake TLS version floor (SEC-9 on device)', () => {
  it('ranks TLS versions so a floor comparison is monotonic', () => {
    expect(tlsVersionRank('TLSv1.3')).toBeGreaterThan(tlsVersionRank('TLSv1.2'));
    expect(tlsVersionRank('TLSv1.2')).toBeGreaterThan(tlsVersionRank('TLSv1.1'));
    expect(tlsVersionRank('TLSv1.1')).toBeGreaterThan(tlsVersionRank('TLSv1'));
    expect(tlsVersionRank('SSLv3')).toBe(0);
    expect(tlsVersionRank('bogus')).toBe(0);
  });

  it('aborts when the negotiated version is below the configured minimum', async () => {
    // The transport reports a downgraded handshake (TLS 1.1). Even though the
    // fake "handshake" succeeded, the engine must refuse before AUTH/send.
    const sock = new FakeSocket({ protocol: 'TLSv1.1' });
    startImplicit(sock);
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      tlsUpgradeOptions: { host: 'test.local', servername: 'test.local', minVersion: 'TLSv1.2' },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    // Nothing sensitive was sent over the weak channel.
    expect(sock.writtenText()).not.toMatch(/^AUTH /m);
    expect(sock.destroyed).toBe(true);
  });

  it('accepts a handshake that meets the minimum', async () => {
    const sock = new FakeSocket({ protocol: 'TLSv1.3' });
    startImplicit(sock);
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      tlsUpgradeOptions: { host: 'test.local', servername: 'test.local', minVersion: 'TLSv1.2' },
    });
    const caps = await client.connect();
    expect(caps.smtpUtf8).toBe(true);
    client.close();
  });

  it('is a no-op when the transport cannot report a protocol (best effort)', async () => {
    // No `protocol` option => getProtocol returns undefined; the floor check must
    // not falsely reject when it has no data to act on.
    const sock = new FakeSocket();
    startImplicit(sock);
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      tlsUpgradeOptions: { host: 'test.local', servername: 'test.local', minVersion: 'TLSv1.2' },
    });
    const caps = await client.connect();
    expect(caps.smtpUtf8).toBe(true);
    client.close();
  });
});
