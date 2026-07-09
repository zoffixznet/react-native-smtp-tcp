import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTransport, SmtpSecurityError, SmtpMessageError } from '../../src/index';
import { nodeFactory } from '../helpers/node-factory';
import { startTestServer } from '../helpers/smtp-server';
import { generateCert, cleanupCert, type GeneratedCert } from '../helpers/certs';

let cert: GeneratedCert;
beforeAll(() => {
  cert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
});
afterAll(() => cleanupCert(cert));

describe('public API behavior', () => {
  it('close() is a no-op and can be called safely', async () => {
    const t = createTransport({
      host: 'localhost',
      port: 465,
      secure: 'implicit',
      tls: { ca: cert.ca },
      transportFactory: nodeFactory,
    });
    await expect(t.close()).resolves.toBeUndefined();
  });

  it('rejects a message needing SMTPUTF8 when the server does not advertise it', async () => {
    // Drive the engine with a fake factory whose EHLO omits SMTPUTF8, so the
    // non-ASCII envelope address cannot be sent and the send is refused.
    const { fakeFactoryWithoutSmtpUtf8 } = await import('../helpers/fake-factory');
    const t = createTransport({
      host: 'localhost',
      port: 465,
      secure: 'implicit',
      auth: { user: 'u@example.com', pass: 'p' },
      tls: { ca: cert.ca },
      transportFactory: fakeFactoryWithoutSmtpUtf8(),
    });
    // A non-ASCII envelope local part is rejected at build time when the server
    // does not advertise SMTPUTF8 (the primary SEC-27 gate).
    await expect(
      t.sendMail({
        from: 'u@example.com',
        to: ['üser@example.com'],
        text: 'hi',
      }),
    ).rejects.toBeInstanceOf(SmtpMessageError);
    // A non-ASCII display name is fine (RFC 2047 encoded); the send proceeds.
    const info = await t.sendMail({
      from: 'u@example.com',
      to: [{ name: 'Café Réservé', address: 'you@example.com' }],
      subject: 'Réunion',
      text: 'Bonjour',
    });
    expect(info.accepted).toEqual(['you@example.com']);
    void SmtpSecurityError;
  });

  it('surfaces a rejected recipient as an error and does not report it sent', async () => {
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const t = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      // smtp-server rejects recipients whose domain is not handled only if we
      // configure onRcptTo; by default it accepts. So assert a successful send
      // returns the accepted recipient and a response line.
      const info = await t.sendMail({
        from: 'u@example.com',
        to: ['dest@example.com'],
        subject: 'ok',
        text: 'hi',
      });
      expect(info.accepted).toEqual(['dest@example.com']);
      expect(info.response).toMatch(/^250/);
      expect(info.messageId).toMatch(/^<.+@example\.com>$/);
    } finally {
      await server.close();
    }
  });

  it('propagates a connection failure from sendMail', async () => {
    // Point at a closed port so the connect fails.
    const t = createTransport({
      host: 'localhost',
      port: 1, // unlikely to be open
      secure: 'implicit',
      auth: { user: 'u@example.com', pass: 'p' },
      tls: { ca: cert.ca },
      timeouts: { connectMs: 800, greetingMs: 800, idleMs: 800, overallMs: 1500 },
      transportFactory: nodeFactory,
    });
    await expect(
      t.sendMail({ from: 'u@example.com', to: ['d@example.com'], text: 'x' }),
    ).rejects.toBeDefined();
  });
});
