/**
 * The device path relies on the native TLS handshake (chain + hostname) and the
 * JS layer no longer parses certificates for hostname matching. These tests
 * drive the public API with a transport that, like the on-device native socket,
 * completes the handshake and exposes the peer certificate asynchronously. They
 * prove:
 *
 *   - with no pin, a completed handshake authenticates and sends (JS does not
 *     re-check identity), and
 *   - with an optional certificate-fingerprint pin, a mismatch fails closed with
 *     a SmtpSecurityError before AUTH, and a match proceeds.
 */
import { describe, it, expect } from 'vitest';
import { createTransport } from '../src/index';
import type { TransportFactory } from '../src/index';
import { SmtpSecurityError } from '../src/protocol/errors';
import { FakeSocket } from './helpers/fake-socket';
import { driveFake } from './helpers/fake-driver';
import type { PeerCertificate } from '../src/protocol/types';

const EHLO = '250-test.local\r\n250-AUTH PLAIN\r\n250 SMTPUTF8\r\n';

/**
 * A factory that mimics the on-device transport: the "socket" completes the
 * handshake, then resolves `getPeerCertificate()` asynchronously to the given
 * certificate (the real native shape: fingerprints + base64 pubkey, no SAN).
 */
function factoryWithCert(peerCertificate: PeerCertificate | undefined): TransportFactory {
  const build = (): FakeSocket => {
    const sock = new FakeSocket({ peerCertificate, asyncPeerCertificate: true });
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local ESMTP\r\n');
    });
    driveFake(sock, [
      { when: /^EHLO /m, reply: EHLO, once: true },
      { when: /^AUTH PLAIN /m, reply: '235 ok\r\n', once: true },
      { when: /^QUIT/m, reply: '221 bye\r\n', once: true },
    ]);
    return sock;
  };
  return { connectImplicitTls: () => build(), connectPlain: () => build() };
}

function transportFor(
  peerCertificate: PeerCertificate | undefined,
  pinnedCertSha256?: string,
) {
  return createTransport({
    host: 'mail.example.com',
    port: 465,
    secure: 'implicit',
    auth: { user: 'u@example.com', pass: 'p' },
    tls: pinnedCertSha256 ? { pinnedCertSha256 } : undefined,
    transportFactory: factoryWithCert(peerCertificate),
  });
}

describe('device path relies on the native handshake', () => {
  it('authenticates over a completed handshake when no pin is configured', async () => {
    // The native handshake verified chain + hostname; JS does not re-check.
    const t = transportFor({ fingerprint256: 'AA:BB:CC' });
    const res = await t.verify();
    expect(res.capabilities.smtpUtf8).toBe(true);
  });

  it('authenticates even when no peer certificate is exposed (handshake is authoritative)', async () => {
    const t = transportFor(undefined);
    await expect(t.verify()).resolves.toBeDefined();
  });
});

describe('optional certificate-fingerprint pin fails closed', () => {
  it('rejects a pin mismatch before AUTH', async () => {
    const t = transportFor({ fingerprint256: 'AA:BB:CC:DD' }, 'ff:ee:dd:cc');
    await expect(t.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  it('fails closed when a pin is configured but no certificate is available', async () => {
    const t = transportFor(undefined, 'aa:bb:cc');
    await expect(t.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  it('proceeds when the pinned fingerprint matches (async cert shape)', async () => {
    const t = transportFor({ fingerprint256: 'AA:BB:CC:DD' }, 'aabbccdd');
    await expect(t.verify()).resolves.toBeDefined();
  });
});
