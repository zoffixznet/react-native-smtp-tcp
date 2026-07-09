/**
 * A real in-process SMTP server (the `smtp-server` package) wired for tests. It
 * supports plaintext+STARTTLS and implicit TLS, records authentications and
 * received messages byte-for-byte, and lets a test assert what the client
 * actually sent over the wire.
 */

import { SMTPServer, type SMTPServerOptions } from 'smtp-server';
import type { AddressInfo } from 'net';
import { Buffer } from 'buffer';

export interface CapturedMessage {
  from: string;
  to: string[];
  /** The raw DATA payload as received (dot-unstuffed by the server). */
  raw: string;
}

export interface CapturedAuth {
  method: string;
  username?: string;
  password?: string;
  accessToken?: string;
}

export interface TestServer {
  port: number;
  messages: CapturedMessage[];
  auths: CapturedAuth[];
  close(): Promise<void>;
}

export interface TestServerOptions {
  secure?: boolean;
  cert?: string;
  key?: string;
  ca?: string;
  /** Expected credentials; auth succeeds only if they match (when set). */
  expectUser?: string;
  expectPass?: string;
  expectToken?: string;
  authMethods?: string[];
  hideSTARTTLS?: boolean;
  minVersion?: string;
  maxVersion?: string;
  ciphers?: string;
  /** When true, advertise SMTPUTF8. */
  smtpUtf8?: boolean;
}

export async function startTestServer(opts: TestServerOptions = {}): Promise<TestServer> {
  const messages: CapturedMessage[] = [];
  const auths: CapturedAuth[] = [];

  const serverOptions: SMTPServerOptions = {
    secure: opts.secure ?? false,
    authOptional: false,
    disabledCommands: [],
    hideSTARTTLS: opts.hideSTARTTLS ?? false,
    authMethods: opts.authMethods ?? ['PLAIN', 'LOGIN', 'XOAUTH2'],
    key: opts.key,
    cert: opts.cert,
    ca: opts.ca ? [opts.ca] : undefined,
    minVersion: opts.minVersion as never,
    maxVersion: opts.maxVersion as never,
    ciphers: opts.ciphers,
    logger: false,
    onAuth(auth, _session, callback) {
      const captured: CapturedAuth = { method: auth.method };
      if (auth.username) captured.username = auth.username;
      if (auth.password) captured.password = auth.password;
      if ((auth as { accessToken?: string }).accessToken) {
        captured.accessToken = (auth as { accessToken?: string }).accessToken;
      }
      auths.push(captured);

      if (auth.method === 'XOAUTH2') {
        if (opts.expectToken && (auth as { accessToken?: string }).accessToken !== opts.expectToken) {
          return callback(new Error('Invalid token'));
        }
        return callback(null, { user: auth.username });
      }
      if (opts.expectUser !== undefined || opts.expectPass !== undefined) {
        if (auth.username !== opts.expectUser || auth.password !== opts.expectPass) {
          return callback(new Error('Invalid credentials'));
        }
      }
      return callback(null, { user: auth.username });
    },
    onData(stream, session, callback) {
      const chunks: Buffer[] = [];
      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('end', () => {
        messages.push({
          from: session.envelope.mailFrom ? (session.envelope.mailFrom as { address: string }).address : '',
          to: session.envelope.rcptTo.map((r) => r.address),
          raw: Buffer.concat(chunks).toString('utf8'),
        });
        callback();
      });
    },
  };

  const server = new SMTPServer(serverOptions);
  await new Promise<void>((resolve, reject) => {
    server.on('error', () => {
      /* swallow adversarial errors */
    });
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const port = (server.server.address() as AddressInfo).port;

  return {
    port,
    messages,
    auths,
    close() {
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
