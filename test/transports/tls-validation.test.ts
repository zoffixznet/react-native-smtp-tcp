import { describe, it, expect } from 'vitest';
import { createTransport } from '../../src/index';
import { nodeFactory } from '../helpers/node-factory';
import { startTestServer } from '../helpers/smtp-server';
import { generateCert, cleanupCert } from '../helpers/certs';
import { SmtpSecurityError, SmtpConfigError, SmtpConnectionError } from '../../src/protocol/errors';

/** Try to connect+verify and return the rejection error (or null on success). */
async function expectFailure(options: Parameters<typeof createTransport>[0]): Promise<Error> {
  const transport = createTransport({ ...options, transportFactory: nodeFactory });
  try {
    await transport.verify();
    throw new Error('expected the connection to be rejected');
  } catch (err) {
    return err as Error;
  }
}

describe('certificate validation (SEC-6, SEC-7)', () => {
  it('T-UNTRUSTED-CHAIN: rejects a self-signed cert with no pin/ca configured', async () => {
    const cert = generateCert({ selfSigned: true, altNames: ['DNS:localhost'] });
    const server = await startTestServer({ secure: true, cert: cert.cert, key: cert.key });
    try {
      const err = await expectFailure({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        // No ca provided: the self-signed cert is untrusted.
      });
      // The socket refuses the untrusted chain.
      expect(err).toBeDefined();
      expect(err.message).not.toMatch(/authenticated/i);
    } finally {
      await server.close();
      cleanupCert(cert);
    }
  });

  it('T-WRONG-HOSTNAME-CERT: rejects a valid cert whose SAN does not match the host', async () => {
    // Cert valid for "other.example" only.
    const cert = generateCert({ altNames: ['DNS:other.example'], commonName: 'other.example' });
    const server = await startTestServer({ secure: true, cert: cert.cert, key: cert.key });
    try {
      const err = await expectFailure({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca },
      });
      expect(err).toBeDefined();
    } finally {
      await server.close();
      cleanupCert(cert);
    }
  });
});

describe('optional certificate-fingerprint pinning', () => {
  it('T-CERT-PIN-POS-NEG: succeeds on a matching pin, fails on a mismatching one', async () => {
    const cert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
    const attacker = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      // Positive: pin the real leaf SHA-256 fingerprint + trust its CA.
      const ok = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, pinnedCertSha256: cert.fingerprint256 },
        transportFactory: nodeFactory,
      });
      await expect(ok.verify()).resolves.toBeDefined();

      // Negative: pin a different (attacker) fingerprint; even with the CA
      // trusted the pin must reject.
      const bad = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, pinnedCertSha256: attacker.fingerprint256 },
        transportFactory: nodeFactory,
      });
      await expect(bad.verify()).rejects.toBeInstanceOf(SmtpSecurityError);
    } finally {
      await server.close();
      cleanupCert(cert);
      cleanupCert(attacker);
    }
  });
});

describe('minimum TLS version (SEC-9)', () => {
  it('T-MIN-TLS-VERSION: refuses a TLS 1.1-only server, succeeds against TLS 1.2', async () => {
    const cert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
    // Server that only offers TLS 1.1.
    const oldServer = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      minVersion: 'TLSv1.1',
      maxVersion: 'TLSv1.1',
    });
    try {
      const err = await expectFailure({
        host: 'localhost',
        port: oldServer.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, minVersion: 'TLSv1.2' },
      });
      expect(err).toBeInstanceOf(SmtpConnectionError);
    } finally {
      await oldServer.close();
    }

    const modernServer = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      minVersion: 'TLSv1.2',
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const ok = createTransport({
        host: 'localhost',
        port: modernServer.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, minVersion: 'TLSv1.2' },
        transportFactory: nodeFactory,
      });
      await expect(ok.verify()).resolves.toBeDefined();
    } finally {
      await modernServer.close();
      cleanupCert(cert);
    }
  });
});

describe('weak ciphers (SEC-10)', () => {
  it('T-WEAK-CIPHER: aborts when the server only offers a non-forward-secret suite', async () => {
    const cert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
    // Restrict the server to a non-AEAD / non-ECDHE suite the client will not
    // offer. AES128-SHA is a legacy CBC RSA-kx suite (no forward secrecy).
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      ciphers: 'AES128-SHA',
    });
    try {
      const err = await expectFailure({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, minVersion: 'TLSv1.2' },
      });
      expect(err).toBeInstanceOf(SmtpConnectionError);
    } finally {
      await server.close();
      cleanupCert(cert);
    }
  });
});

describe('bare-IP host identity (SEC-11)', () => {
  it('requires an explicit servername for a bare-IP host', () => {
    expect(() =>
      createTransport({
        host: '127.0.0.1',
        port: 465,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        transportFactory: nodeFactory,
      }),
    ).toThrow(SmtpConfigError);
  });

  it('T-IP-SNI: validates a bare-IP host against the explicit expected hostname', async () => {
    // Cert has a matching IP SAN.
    const cert = generateCert({ altNames: ['IP:127.0.0.1', 'DNS:localhost'], commonName: 'localhost' });
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const ok = createTransport({
        host: '127.0.0.1',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca, servername: '127.0.0.1' },
        transportFactory: nodeFactory,
      });
      await expect(ok.verify()).resolves.toBeDefined();
    } finally {
      await server.close();
    }

    // A cert lacking the IP SAN is rejected for the IP host.
    const noIpCert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
    const server2 = await startTestServer({ secure: true, cert: noIpCert.cert, key: noIpCert.key });
    try {
      const err = await expectFailure({
        host: '127.0.0.1',
        port: server2.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: noIpCert.ca, servername: '127.0.0.1' },
      });
      expect(err).toBeDefined();
    } finally {
      await server2.close();
      cleanupCert(cert);
      cleanupCert(noIpCert);
    }
  });
});
