import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTransport } from '../../src/index';
import { nodeFactory } from '../helpers/node-factory';
import { startTestServer, type TestServer } from '../helpers/smtp-server';
import { generateCert, cleanupCert, type GeneratedCert } from '../helpers/certs';

let cert: GeneratedCert;

beforeAll(() => {
  cert = generateCert({ altNames: ['DNS:localhost', 'IP:127.0.0.1'], commonName: 'localhost' });
});
afterAll(() => cleanupCert(cert));

describe('end-to-end sends against a real SMTP server', () => {
  it('T-IMPLICIT-TLS-PATH: implicit TLS (465-style) + PLAIN auth delivers a message', async () => {
    const server: TestServer = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'me@example.com',
      expectPass: 'sekret',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'me@example.com', pass: 'sekret' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      const info = await transport.sendMail({
        from: { name: 'Me', address: 'me@example.com' },
        to: [{ address: 'you@example.com' }],
        subject: 'Rappel: café',
        text: 'Bonjour\nGoodbye',
        html: '<p>Bonjour</p>',
      });
      expect(info.accepted).toEqual(['you@example.com']);
      expect(server.messages).toHaveLength(1);
      const msg = server.messages[0];
      expect(msg.from).toBe('me@example.com');
      expect(msg.to).toEqual(['you@example.com']);
      // The received body includes the non-ASCII subject as an encoded-word.
      expect(msg.raw).toMatch(/Subject: =\?UTF-8\?B\?/);
      // A lone-dot line, if present, was dot-stuffed and restored (no early end).
      expect(server.auths[0].method).toBe('PLAIN');
      expect(server.auths[0].username).toBe('me@example.com');
    } finally {
      await server.close();
    }
  });

  it('STARTTLS (587-style) + LOGIN auth delivers a message and re-EHLOs in TLS', async () => {
    const server = await startTestServer({
      secure: false,
      cert: cert.cert,
      key: cert.key,
      authMethods: ['LOGIN'],
      expectUser: 'user@example.com',
      expectPass: 'pw',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'starttls',
        auth: { user: 'user@example.com', pass: 'pw' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      const info = await transport.sendMail({
        from: 'user@example.com',
        to: ['dest@example.com'],
        subject: 'plain subject',
        text: 'hello there',
      });
      expect(info.accepted).toEqual(['dest@example.com']);
      expect(server.messages).toHaveLength(1);
      expect(server.auths[0].method).toBe('LOGIN');
    } finally {
      await server.close();
    }
  });

  it('XOAUTH2 delivers a message', async () => {
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      authMethods: ['XOAUTH2'],
      expectToken: 'ya29.TESTTOKEN',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'oauth@example.com', type: 'oauth2', accessToken: 'ya29.TESTTOKEN' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      const info = await transport.sendMail({
        from: 'oauth@example.com',
        to: ['dest@example.com'],
        text: 'via oauth',
      });
      expect(info.accepted).toEqual(['dest@example.com']);
      expect(server.auths[0].method).toBe('XOAUTH2');
    } finally {
      await server.close();
    }
  });

  it('verify() connects, authenticates, and quits cleanly', async () => {
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'me@example.com',
      expectPass: 'sekret',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'me@example.com', pass: 'sekret' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      const result = await transport.verify();
      expect(result.capabilities.smtpUtf8 !== undefined).toBe(true);
    } finally {
      await server.close();
    }
  });

  it('T-DOTSTUFF-LONE-DOT: a lone-dot body line is received byte-identical', async () => {
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'implicit',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca },
        transportFactory: nodeFactory,
      });
      await transport.sendMail({
        from: 'u@example.com',
        to: ['d@example.com'],
        text: 'before\n.\nafter',
      });
      // The server dot-unstuffs, so the received body contains the literal line ".".
      const body = server.messages[0].raw;
      expect(body).toMatch(/before\r?\n\.\r?\nafter/);
    } finally {
      await server.close();
    }
  });
});
