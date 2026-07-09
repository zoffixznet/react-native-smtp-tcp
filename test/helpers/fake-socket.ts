/**
 * An in-memory adversarial fake socket implementing SmtpTransport. It gives a
 * test byte-level control over what a hostile server sends and when, and records
 * exactly what the client wrote to the wire. It never touches the network.
 *
 * The test script drives the socket: it can push arbitrary bytes to the client's
 * data handler, emit errors/close at any point, and inspect the written bytes.
 */

import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import type { PeerCertificate, SmtpTransport, TlsUpgradeOptions } from '../../src/protocol/types';

export interface FakeSocketOptions {
  /** A canned peer certificate returned by getPeerCertificate after upgrade. */
  peerCertificate?: PeerCertificate;
  /** When true, upgradeToTLS returns a new FakeSocket that emits secureConnect. */
  supportUpgrade?: boolean;
}

export class FakeSocket extends EventEmitter implements SmtpTransport {
  /** Everything the client wrote, concatenated. */
  public written: Buffer[] = [];
  public destroyed = false;
  public upgradeCalledWith: TlsUpgradeOptions | null = null;
  /** The transport returned by the most recent upgradeToTLS, if any. */
  public upgraded: FakeSocket | null = null;

  private opts: FakeSocketOptions;

  constructor(opts: FakeSocketOptions = {}) {
    super();
    this.setMaxListeners(50);
    this.opts = opts;
  }

  // --- SmtpTransport surface ---------------------------------------------

  write(data: string | Uint8Array, cb?: (err?: Error) => void): boolean {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
    this.written.push(buf);
    if (cb) queueMicrotask(() => cb());
    return true;
  }

  end(data?: string | Uint8Array, cb?: () => void): void {
    if (data !== undefined) this.write(data);
    if (cb) queueMicrotask(cb);
  }

  destroy(_err?: Error): void {
    this.destroyed = true;
    queueMicrotask(() => this.emit('close', Boolean(_err)));
  }

  setTimeout(_ms: number, _cb?: () => void): void {
    // The engine manages its own timers; the fake socket ignores this.
  }

  upgradeToTLS(opts: TlsUpgradeOptions): SmtpTransport {
    this.upgradeCalledWith = opts;
    const next = new FakeSocket(this.opts);
    this.upgraded = next;
    // Signal readiness asynchronously, like a real handshake.
    queueMicrotask(() => next.emit('secureConnect'));
    return next;
  }

  getPeerCertificate(): PeerCertificate | undefined {
    return this.opts.peerCertificate;
  }

  // --- Test controls ------------------------------------------------------

  /** Push raw bytes to the client as if the server sent them. */
  serverSend(data: string | Buffer): void {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    this.emit('data', new Uint8Array(buf));
  }

  /** Emit a socket error. */
  serverError(message: string): void {
    this.emit('error', new Error(message));
  }

  /** Emit a close (had_error flag). */
  serverClose(hadError = false): void {
    this.emit('close', hadError);
  }

  /** Fire the connect event (for the STARTTLS/plain path). */
  fireConnect(): void {
    this.emit('connect');
  }

  /** Fire the secureConnect event (for the implicit-TLS path). */
  fireSecureConnect(): void {
    this.emit('secureConnect');
  }

  /** The full written stream as a UTF-8 string. */
  writtenText(): string {
    return Buffer.concat(this.written).toString('utf8');
  }

  /** The full written stream as a Buffer. */
  writtenBuffer(): Buffer {
    return Buffer.concat(this.written);
  }
}
