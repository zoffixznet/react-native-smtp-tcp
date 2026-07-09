import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  createTransport,
  selectPlainConnect,
  selectImplicitConnect,
  type RnStyleAdapter,
} from '../../src/index';
import { resolveConfig } from '../../src/config';
import { FakeSocket } from '../helpers/fake-socket';
import {
  connectPlain,
  connectImplicitTls,
  wrapNodeSocket,
} from '../../src/transports/node';
import { startTestServer } from '../helpers/smtp-server';
import { generateCert, cleanupCert, type GeneratedCert } from '../helpers/certs';
import net from 'net';

let cert: GeneratedCert;
beforeAll(() => {
  cert = generateCert({ altNames: ['DNS:localhost'], commonName: 'localhost' });
});
afterAll(() => cleanupCert(cert));

describe('Node adapter and default factory', () => {
  it('the default factory (no injected transportFactory) sends via the Node adapter', async () => {
    // In this Node environment react-native-tcp-socket is not installed, so the
    // default factory falls back to the Node adapter. This exercises index.ts's
    // default factory and the RN-adapter lookup miss path.
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
        // No transportFactory: uses the default.
      });
      const info = await transport.sendMail({
        from: 'u@example.com',
        to: ['d@example.com'],
        text: 'via default factory',
      });
      expect(info.accepted).toEqual(['d@example.com']);
    } finally {
      await server.close();
    }
  });

  it('the default factory also works over STARTTLS', async () => {
    const server = await startTestServer({
      secure: false,
      cert: cert.cert,
      key: cert.key,
      authMethods: ['PLAIN'],
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const transport = createTransport({
        host: 'localhost',
        port: server.port,
        secure: 'starttls',
        auth: { user: 'u@example.com', pass: 'p' },
        tls: { ca: cert.ca },
      });
      const info = await transport.sendMail({
        from: 'u@example.com',
        to: ['d@example.com'],
        text: 'via default starttls',
      });
      expect(info.accepted).toEqual(['d@example.com']);
    } finally {
      await server.close();
    }
  });

  it('the plain adapter exposes the SmtpTransport surface (write/end/destroy/listeners)', async () => {
    const server = net.createServer((s) => {
      s.on('data', () => s.write('ok'));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as net.AddressInfo).port;
    const t = connectPlain({
      host: '127.0.0.1',
      port,
      connectTimeoutMs: 1000,
      servername: '127.0.0.1',
      tls: {},
    });
    await new Promise<void>((resolve) => t.once('connect', () => resolve()));
    let got = false;
    t.on('data', () => (got = true));
    t.setTimeout(5000);
    t.write('ping');
    await new Promise((r) => setTimeout(r, 50));
    expect(got).toBe(true);
    // getPeerCertificate returns undefined on a plain socket.
    expect(t.getPeerCertificate?.()).toBeUndefined();
    expect(t.getProtocol?.()).toBeUndefined();
    t.removeAllListeners('data');
    t.end();
    t.destroy();
    server.close();
  });

  it('getPeerCertificate and getProtocol return values on a TLS socket', async () => {
    const server = await startTestServer({
      secure: true,
      cert: cert.cert,
      key: cert.key,
      expectUser: 'u@example.com',
      expectPass: 'p',
    });
    try {
      const t = connectImplicitTls({
        host: 'localhost',
        port: server.port,
        connectTimeoutMs: 2000,
        servername: 'localhost',
        tls: { ca: cert.ca, servername: 'localhost' },
      });
      await new Promise<void>((resolve, reject) => {
        t.once('secureConnect', () => resolve());
        t.once('error', reject);
      });
      const peer = t.getPeerCertificate?.();
      expect(peer).toBeDefined();
      expect(peer?.subjectAltNames).toContain('localhost');
      expect(peer?.pubkey).toBeDefined();
      expect(t.getProtocol?.()).toMatch(/TLS/);
      t.destroy();
    } finally {
      await server.close();
    }
  });

  it('wrapNodeSocket wraps an existing socket', () => {
    const s = new net.Socket();
    const t = wrapNodeSocket(s);
    expect(typeof t.write).toBe('function');
    s.destroy();
  });

  it('adapter selection uses the RN adapter when one is provided', () => {
    const config = resolveConfig({ host: 'localhost', port: 465, secure: 'implicit' });
    const calls: string[] = [];
    const stubPlain = new FakeSocket();
    const stubImplicit = new FakeSocket();
    const rn: RnStyleAdapter = {
      connectPlain(o) {
        calls.push(`plain:${o.host}:${o.port}`);
        return stubPlain;
      },
      connectImplicitTls(o) {
        calls.push(`implicit:${o.host}:${o.port}`);
        return stubImplicit;
      },
    };
    const tls = { host: config.host, servername: config.servername };
    expect(selectPlainConnect(config, tls, rn)).toBe(stubPlain);
    expect(selectImplicitConnect(config, tls, rn)).toBe(stubImplicit);
    expect(calls).toEqual(['plain:localhost:465', 'implicit:localhost:465']);
    stubPlain.destroy();
    stubImplicit.destroy();
  });

  it('wraps a stub socket and maps getPeerCertificate/getProtocol fields', () => {
    // A stub socket standing in for a tls.TLSSocket, exercising the field-mapping
    // branches (present and absent) without a live handshake.
    const events: Record<string, unknown> = {};
    const stub = {
      write: () => true,
      end: (..._a: unknown[]) => undefined,
      destroy: () => undefined,
      setTimeout: () => undefined,
      on: () => stub,
      once: () => stub,
      removeListener: () => stub,
      removeAllListeners: () => stub,
      getPeerCertificate: () => ({
        raw: Buffer.from([1, 2, 3]),
        pubkey: Buffer.from([4, 5, 6]),
        fingerprint: 'AA:BB',
        fingerprint256: 'CC:DD',
        subjectaltname: 'DNS:a.example, IP Address:192.0.2.1',
        subject: { CN: 'a.example' },
      }),
      getProtocol: () => 'TLSv1.3',
    };
    void events;
    const t = wrapNodeSocket(stub as never);
    // end with data and without data.
    t.end('bye');
    t.end();
    const peer = t.getPeerCertificate!();
    expect(peer?.subjectAltNames).toEqual(['a.example', '192.0.2.1']);
    expect(peer?.commonName).toBe('a.example');
    expect(peer?.raw).toBeInstanceOf(Uint8Array);
    expect(peer?.pubkey).toBeInstanceOf(Uint8Array);
    expect(t.getProtocol!()).toBe('TLSv1.3');
  });

  it('handles a peer certificate that lacks raw/pubkey/SAN/CN', () => {
    const stub = {
      write: () => true,
      end: () => undefined,
      destroy: () => undefined,
      setTimeout: () => undefined,
      on: () => stub,
      once: () => stub,
      removeListener: () => stub,
      removeAllListeners: () => stub,
      // A minimal cert object: no raw, no pubkey, no SAN, no subject.CN.
      getPeerCertificate: () => ({ fingerprint: 'AA' }),
      getProtocol: () => null,
    };
    const t = wrapNodeSocket(stub as never);
    const peer = t.getPeerCertificate!();
    expect(peer?.raw).toBeUndefined();
    expect(peer?.pubkey).toBeUndefined();
    expect(peer?.commonName).toBeUndefined();
    expect(peer?.subjectAltNames).toEqual([]);
    // getProtocol returning null maps to undefined.
    expect(t.getProtocol!()).toBeUndefined();
  });

  it('returns undefined for an empty peer certificate or missing accessors', () => {
    const stub = {
      write: () => true,
      end: () => undefined,
      destroy: () => undefined,
      setTimeout: () => undefined,
      on: () => stub,
      once: () => stub,
      removeListener: () => stub,
      removeAllListeners: () => stub,
      getPeerCertificate: () => ({}),
    };
    const t = wrapNodeSocket(stub as never);
    expect(t.getPeerCertificate!()).toBeUndefined();
    // No getProtocol function -> undefined.
    expect(t.getProtocol!()).toBeUndefined();
  });

  it('adapter selection falls back to the Node adapter when rn is null', () => {
    const config = resolveConfig({ host: '127.0.0.1', port: 40000, secure: 'starttls', tls: { servername: 'localhost' } });
    const tls = { host: config.host, servername: config.servername };
    const t = selectPlainConnect(config, tls, null);
    expect(typeof t.write).toBe('function');
    t.destroy();
  });
});
