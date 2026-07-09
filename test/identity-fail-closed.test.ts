/**
 * Finding 1: on-device (RN) named-host identity must be verified in JS and must
 * fail closed. These tests drive the public API with a transport that, like the
 * native Android socket, does NOT verify the hostname itself but exposes a peer
 * certificate. The library must reject a mismatching or unusable identity before
 * it authenticates or sends, using the parsed subjectAltName / CN.
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
 * handshake without checking the hostname, then exposes `peerCertificate`.
 */
function factoryWithCert(peerCertificate: PeerCertificate | undefined): TransportFactory {
  const build = (): FakeSocket => {
    const sock = new FakeSocket({ peerCertificate });
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

function transportFor(peerCertificate: PeerCertificate | undefined) {
  return createTransport({
    host: 'mail.example.com',
    port: 465,
    secure: 'implicit',
    auth: { user: 'u@example.com', pass: 'p' },
    transportFactory: factoryWithCert(peerCertificate),
  });
}

/** A bare-IP transport whose expected identity is set via tls.servername. */
function ipTransportFor(peerCertificate: PeerCertificate | undefined) {
  return createTransport({
    host: '192.0.2.10',
    port: 465,
    secure: 'implicit',
    auth: { user: 'u@example.com', pass: 'p' },
    tls: { servername: '192.0.2.10' },
    transportFactory: factoryWithCert(peerCertificate),
  });
}

describe('named-host identity is verified in JS and fails closed (Finding 1)', () => {
  it('rejects a certificate whose SAN does not match the host, before AUTH', async () => {
    // The socket did not check the hostname; the cert is valid for a different
    // name. The JS check must reject it and never authenticate.
    const t = transportFor({ subjectAltNames: ['attacker.example.net'], commonName: 'attacker.example.net' });
    await expect(t.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  it('fails closed when no usable certificate identity is available', async () => {
    // No cert at all: the library must not silently trust the channel.
    const t1 = transportFor(undefined);
    await expect(t1.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
    // A cert object with no SAN parsed (subjectAltNames undefined, e.g. leaf did
    // not parse) must also fail closed rather than pass.
    const t2 = transportFor({ fingerprint: 'AA:BB' });
    await expect(t2.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  it('accepts a certificate whose SAN matches the host', async () => {
    const t = transportFor({ subjectAltNames: ['mail.example.com'], commonName: 'mail.example.com' });
    const res = await t.verify();
    expect(res.capabilities.smtpUtf8).toBe(true);
  });

  it('accepts a matching wildcard SAN but rejects a public-suffix wildcard', async () => {
    const ok = transportFor({ subjectAltNames: ['*.example.com'] });
    await expect(ok.verify()).resolves.toBeDefined();
    // A cert whose only SAN is a TLD-position wildcard must not validate the host.
    const bad = transportFor({ subjectAltNames: ['*.com'] });
    await expect(bad.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  it('accepts a CN-only certificate as a legacy fallback when it matches', async () => {
    // Empty SAN list, CN matches: verifyHostname allows the CN fallback.
    const t = transportFor({ subjectAltNames: [], commonName: 'mail.example.com' });
    await expect(t.verify()).resolves.toBeDefined();
    // Empty SAN list, CN mismatches: rejected.
    const bad = transportFor({ subjectAltNames: [], commonName: 'other.example.com' });
    await expect(bad.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
  });

  describe('bare-IP host identity (SEC-11)', () => {
    it('fails closed when a bare-IP host presents no certificate details', async () => {
      await expect(ipTransportFor(undefined).verify()).rejects.toBeInstanceOf(SmtpSecurityError);
      await expect(
        ipTransportFor({ fingerprint: 'AA' }).verify(),
      ).rejects.toBeInstanceOf(SmtpSecurityError);
    });

    it('rejects a bare-IP host whose cert lacks a matching IP SAN', async () => {
      await expect(
        ipTransportFor({ subjectAltNames: ['192.0.2.99'] }).verify(),
      ).rejects.toBeInstanceOf(SmtpSecurityError);
    });

    it('accepts a bare-IP host whose cert has the matching IP SAN', async () => {
      const t = ipTransportFor({ subjectAltNames: ['192.0.2.10'] });
      await expect(t.verify()).resolves.toBeDefined();
    });
  });
});
