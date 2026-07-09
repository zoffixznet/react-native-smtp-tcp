/**
 * A scriptable in-process SMTP server for adversarial end-to-end tests. It
 * listens on a real TCP port, and a test supplies a handler that reacts to the
 * bytes the client sends. The handler has full control: it can send arbitrary
 * bytes (including malformed replies, injected extra lines, or byte trickles),
 * upgrade to TLS in place for STARTTLS, or drop the connection.
 *
 * This is deliberately low-level so the tests can reproduce the exact hostile
 * behaviors in the must-have test list (residual-bytes injection, no-terminator
 * hangs, slowloris, mid-dialog resets, etc.).
 */

import net from 'net';
import tls from 'tls';
import { AddressInfo } from 'net';

export interface ScriptedConnection {
  /** Send raw bytes to the client. */
  send(data: string | Buffer): void;
  /** Upgrade this connection to TLS in place (for STARTTLS). Returns when the
   * secure socket is ready; subsequent data events are decrypted. */
  startTls(options: tls.TlsOptions): Promise<void>;
  /** Close the underlying socket. */
  close(): void;
  /** Destroy (reset) the underlying socket. */
  destroy(): void;
  /** The current socket (plain or TLS). */
  socket: net.Socket | tls.TLSSocket;
}

export type LineHandler = (line: string, conn: ScriptedConnection) => void | Promise<void>;
export type RawHandler = (chunk: Buffer, conn: ScriptedConnection) => void | Promise<void>;

export interface ScriptedServerOptions {
  /** Bytes sent immediately on connect (the greeting). Omit to send nothing. */
  greeting?: string | null;
  /** Called for each complete CRLF line received (before any TLS upgrade). */
  onLine?: LineHandler;
  /** Called for raw chunks instead of line parsing (full control). */
  onData?: RawHandler;
  /** TLS options if the server implements implicit TLS (port 465 style). */
  implicitTls?: tls.TlsOptions;
}

export interface ScriptedServer {
  port: number;
  close(): Promise<void>;
}

/** Start a scripted server. Returns its port and a close() function. */
export async function startScriptedServer(opts: ScriptedServerOptions): Promise<ScriptedServer> {
  const connections = new Set<net.Socket | tls.TLSSocket>();

  const wire = (socket: net.Socket | tls.TLSSocket) => {
    connections.add(socket);
    let current: net.Socket | tls.TLSSocket = socket;
    let buffer = '';
    let upgraded = false;

    const conn: ScriptedConnection = {
      get socket() {
        return current;
      },
      send(data) {
        current.write(typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
      },
      close() {
        current.end();
      },
      destroy() {
        current.destroy();
      },
      startTls(tlsOptions) {
        return new Promise<void>((resolve) => {
          const secure = new tls.TLSSocket(current, {
            isServer: true,
            ...tlsOptions,
          });
          upgraded = true;
          connections.add(secure);
          current = secure;
          buffer = '';
          secure.on('secure', () => resolve());
          secure.on('data', (chunk: Buffer) => handleChunk(chunk));
          secure.on('error', () => {
            /* ignore adversarial TLS errors */
          });
        });
      },
    };

    const handleChunk = (chunk: Buffer) => {
      if (opts.onData && !upgraded) {
        void opts.onData(chunk, conn);
        return;
      }
      if (opts.onData && upgraded) {
        void opts.onData(chunk, conn);
        return;
      }
      buffer += chunk.toString('utf8');
      let idx: number;
      while ((idx = buffer.indexOf('\r\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        if (opts.onLine) void opts.onLine(line, conn);
      }
    };

    socket.on('data', handleChunk);
    socket.on('error', () => {
      /* ignore */
    });
    socket.on('close', () => connections.delete(socket));

    if (opts.greeting) {
      socket.write(Buffer.from(opts.greeting, 'utf8'));
    } else if (opts.greeting === undefined) {
      // Default greeting when none specified.
      socket.write(Buffer.from('220 test.local ESMTP ready\r\n', 'utf8'));
    }
    // greeting === null means send nothing (for no-greeting tests).
  };

  const server = opts.implicitTls
    ? tls.createServer(opts.implicitTls, (s) => wire(s))
    : net.createServer((s) => wire(s));

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as AddressInfo).port;

  return {
    port,
    close() {
      return new Promise<void>((resolve) => {
        for (const c of connections) c.destroy();
        server.close(() => resolve());
      });
    },
  };
}
