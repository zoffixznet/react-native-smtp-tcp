import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { startScriptedServer } from '../helpers/scripted-server';
import { connectPlain } from '../../src/transports/node';
import {
  SmtpConnectionError,
  SmtpProtocolError,
  SmtpTimeoutError,
} from '../../src/protocol/errors';

const SHORT = { connectMs: 2000, greetingMs: 800, idleMs: 800, overallMs: 1500 };

/** Connect the engine to a scripted server over a real Node plain socket. */
function connectEngineToServer(host: string, port: number, overrides = {}) {
  const transport = connectPlain({
    host,
    port,
    connectTimeoutMs: 2000,
    servername: host,
    tls: { host, servername: host },
  });
  return makeClient(transport, {
    host,
    secure: 'starttls',
    requireTLS: false, // these tests exercise failures before/around TLS
    timeouts: SHORT,
    ...overrides,
  });
}

describe('mid-dialog failures (SEC-23)', () => {
  it('T-MID-DIALOG-RST: a reset during DATA is treated as not-sent', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      sock.serverSend('220 test.local\r\n');
    });
    driveFake(sock, [
      { when: /^EHLO /m, reply: '250 test.local\r\n', once: true },
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      // On the message body, the server resets instead of replying.
      { when: /\r\n\.\r\n/, reply: '', then: (s) => s.destroy(), once: true },
    ]);
    const client = makeClient(sock, { secure: 'implicit', requireTLS: false });
    await client.connect();
    await expect(
      client.sendTransaction({
        from: 'me@example.com',
        to: ['you@example.com'],
        data: 'Subject: x\r\n\r\nx\r\n',
        sizeBytes: 20,
        smtpUtf8: false,
        eightBitMime: false,
      }),
    ).rejects.toBeInstanceOf(SmtpConnectionError);
  });

  it('T-PARTIAL-EOF: a partial reply then EOF is not success', async () => {
    const sock = new FakeSocket();
    queueMicrotask(() => {
      sock.fireSecureConnect();
      // "250-a" then EOF: never a complete final reply.
      sock.serverSend('250-a\r\n250');
      sock.serverClose(false);
    });
    const client = makeClient(sock, { secure: 'implicit', requireTLS: false });
    await expect(client.connect()).rejects.toBeInstanceOf(SmtpConnectionError);
  });
});

describe('timeouts and slowloris (SEC-22)', () => {
  it('T-NO-GREETING: greeting timeout fires when no banner arrives', async () => {
    const server = await startScriptedServer({ greeting: null });
    try {
      const client = connectEngineToServer('127.0.0.1', server.port);
      await expect(client.connect()).rejects.toBeInstanceOf(SmtpTimeoutError);
    } finally {
      await server.close();
    }
  });

  it('T-NO-TERMINATOR: a reply with no CRLF eventually times out', async () => {
    const server = await startScriptedServer({
      greeting: '220 test.local\r\n',
      onLine: (line, conn) => {
        if (/^EHLO/i.test(line)) {
          // Send a reply with no terminating CRLF and then hold the connection.
          conn.send('250 ok'); // no CRLF, never completes
        }
      },
    });
    try {
      const client = connectEngineToServer('127.0.0.1', server.port);
      await expect(client.connect()).rejects.toBeInstanceOf(SmtpTimeoutError);
    } finally {
      await server.close();
    }
  });

  it('T-SLOWLORIS: a byte trickle under the idle window still hits the overall deadline', async () => {
    const server = await startScriptedServer({
      greeting: '220 test.local\r\n',
      onLine: (line, conn) => {
        if (/^EHLO/i.test(line)) {
          // Drip one byte every 400ms; idle is 800ms so idle never fires, but the
          // 1500ms overall deadline must.
          const payload = '250 okokokokokokokokok\r\n';
          let i = 0;
          const timer = setInterval(() => {
            if (i >= payload.length) {
              clearInterval(timer);
              return;
            }
            conn.send(payload[i++]);
          }, 400);
        }
      },
    });
    try {
      const client = connectEngineToServer('127.0.0.1', server.port);
      await expect(client.connect()).rejects.toBeInstanceOf(SmtpTimeoutError);
    } finally {
      await server.close();
    }
  });
});

describe('malformed dialog over a real socket', () => {
  it('T-MULTILINE-MISMATCH: mismatched continuation code aborts', async () => {
    const server = await startScriptedServer({
      greeting: '220 test.local\r\n',
      onLine: (line, conn) => {
        if (/^EHLO/i.test(line)) conn.send('250-hello\r\n500 boom\r\n');
      },
    });
    try {
      const client = connectEngineToServer('127.0.0.1', server.port);
      await expect(client.connect()).rejects.toBeInstanceOf(SmtpProtocolError);
    } finally {
      await server.close();
    }
  });
});
