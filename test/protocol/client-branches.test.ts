import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import {
  SmtpProtocolError,
  SmtpSecurityError,
  SmtpAuthError,
} from '../../src/protocol/errors';

const EHLO = '250-test.local\r\n250-SIZE 100000\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket, ehlo = EHLO): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  driveFake(sock, [{ when: /^EHLO /m, reply: ehlo, once: true }]);
}

async function connect(sock: FakeSocket, overrides = {}) {
  const client = makeClient(sock, { secure: 'implicit', requireTLS: true, ...overrides });
  await client.connect();
  return client;
}

const TX = {
  from: 'me@example.com',
  to: ['you@example.com'],
  data: 'Subject: x\r\n\r\nbody\r\n',
  sizeBytes: 20,
  smtpUtf8: false,
  eightBitMime: false,
};

describe('transaction branches', () => {
  it('emits SMTPUTF8 on MAIL FROM when negotiated and needed', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connect(sock);
    await client.sendTransaction({ ...TX, smtpUtf8: true });
    expect(sock.writtenText()).toMatch(/MAIL FROM:<me@example\.com> SIZE=20 SMTPUTF8/);
    client.close();
  });

  it('treats a 4xx RCPT as a transient failure and RSETs', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '451 4.3.0 try later\r\n', once: true },
      { when: /^RSET/m, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connect(sock);
    await expect(client.sendTransaction(TX)).rejects.toMatchObject({ transient: true });
    client.close();
  });

  it('reports a DATA-phase 552 rejection as not accepted', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '552 5.3.4 message too big\r\n', once: true },
    ]);
    const client = await connect(sock);
    await expect(client.sendTransaction(TX)).rejects.toBeInstanceOf(SmtpProtocolError);
    client.close();
  });

  it('aborts when TLS channel verification fails (identity/pin)', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    // verifyTlsChannel throws (e.g. hostname mismatch or pin failure), so the
    // connection must abort before EHLO/AUTH.
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      verifyTlsChannel: () => {
        throw new SmtpSecurityError('identity check failed');
      },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
    // Nothing was sent after the failed verification.
    expect(sock.writtenText()).not.toMatch(/^AUTH /m);
  });

  it('wraps a non-security verification error as a security error', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      verifyTlsChannel: () => {
        throw new Error('some low-level failure');
      },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpSecurityError);
  });
});

describe('AUTH XOAUTH2 mid-exchange and errors', () => {
  it('XOAUTH2 success without an error challenge', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 AUTH XOAUTH2\r\n');
    driveFake(sock, [{ when: /^AUTH XOAUTH2 /m, reply: '235 2.7.0 ok\r\n', once: true }]);
    const client = await connect(sock, {
      auth: { user: 'u@example.com', type: 'oauth2', accessToken: 'TOK' },
    });
    client.close();
    expect(sock.writtenText()).toMatch(/^AUTH XOAUTH2 /m);
  });

  it('uses a token provider (refresh hook)', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 AUTH XOAUTH2\r\n');
    driveFake(sock, [{ when: /^AUTH XOAUTH2 /m, reply: '235 ok\r\n', once: true }]);
    let called = false;
    const client = await connect(sock, {
      auth: {
        user: 'u@example.com',
        type: 'oauth2',
        tokenProvider: async () => {
          called = true;
          return 'FRESH_TOKEN';
        },
      },
    });
    expect(called).toBe(true);
    client.close();
  });

  it('surfaces a token-provider failure as a generic auth error', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 AUTH XOAUTH2\r\n');
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: {
        user: 'u@example.com',
        type: 'oauth2',
        tokenProvider: async () => '',
      },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpAuthError);
  });
});

describe('more transaction and connect branches', () => {
  it('omits SIZE on MAIL FROM when the server does not advertise SIZE', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 8BITMIME\r\n');
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 ok\r\n', once: true },
    ]);
    const client = await connect(sock);
    await client.sendTransaction(TX);
    // No SIZE parameter on the MAIL FROM line.
    expect(sock.writtenText()).toMatch(/^MAIL FROM:<me@example\.com>\r\n/m);
    client.close();
  });

  it('aborts the dialog when a reply line exceeds the DoS cap', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      // Reply to MAIL FROM with a line far over the maxLineBytes cap, no CRLF.
      { when: /^MAIL FROM:/m, reply: '250 ' + 'a'.repeat(20000), once: true },
    ]);
    const client = await connect(sock, {
      caps: { maxLineBytes: 4096, maxReplyBytes: 65536, maxContinuationLines: 200 },
    });
    await expect(client.sendTransaction(TX)).rejects.toBeInstanceOf(SmtpProtocolError);
  });

  it('a connection error during the TLS handshake rejects connect', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => sock.serverError('handshake reset'));
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await expect(client.connect()).rejects.toBeDefined();
  });

  it('a plaintext connection error during connect rejects', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => sock.serverError('connection refused'));
    const client = makeClient(sock, { secure: 'starttls', requireTLS: false });
    await expect(client.connect()).rejects.toBeDefined();
  });
});

describe('LOGIN mid-exchange failures and logging', () => {
  it('surfaces a non-334 reply to AUTH LOGIN as a generic failure', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '250-test.local\r\n250 AUTH LOGIN\r\n');
    driveFake(sock, [{ when: /^AUTH LOGIN/m, reply: '535 nope\r\n', once: true }]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'u@example.com', pass: 'p' },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpAuthError);
  });

  it('surfaces a failure after the username 334', async () => {
    const sock = new FakeSocket();
    const b64 = (s: string) => Buffer.from(s).toString('base64');
    void b64;
    startImplicit(sock, '250-test.local\r\n250 AUTH LOGIN\r\n');
    driveFake(sock, [
      { when: /^AUTH LOGIN/m, reply: '334 VXNlcm5hbWU6\r\n', once: true },
      // After the username, respond with a failure instead of the password 334.
      { when: /^(?!AUTH)[A-Za-z0-9+/=]+\r\n/m, reply: '535 bad\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      auth: { user: 'alice', pass: 'secret' },
      logger: { debug: () => undefined },
    });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpAuthError);
  });
});

describe('capability parsing edge cases', () => {
  it('ignores blank continuation lines and records the greeting', async () => {
    const sock = new FakeSocket();
    // EHLO with a blank capability line in the middle.
    startImplicit(sock, '250-test.local greeting\r\n250-\r\n250 SMTPUTF8\r\n');
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    const caps = await client.connect();
    expect(caps.greeting).toContain('test.local');
    expect(caps.smtpUtf8).toBe(true);
    client.close();
  });
});

describe('greeting and EHLO error branches', () => {
  it('rejects a non-220 greeting', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('554 no service\r\n');
    });
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpProtocolError);
  });

  it('rejects a permanent EHLO failure that is not 500/502', async () => {
    const sock = new FakeSocket();
    startImplicit(sock, '');
    driveFake(sock, [{ when: /^EHLO /m, reply: '550 go away\r\n', once: true }]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: true });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpProtocolError);
  });
});
