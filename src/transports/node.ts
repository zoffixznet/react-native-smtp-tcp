/**
 * Node net/tls adapter implementing {@link SmtpTransport}.
 *
 * This adapter is used by the test suite. It connects with certificate chain
 * and hostname validation on (rejectUnauthorized), sets a minimum TLS version
 * and an AEAD cipher list, and exposes the peer certificate for the optional
 * fingerprint pin.
 *
 * It is one of two places (with the React Native adapter) that import platform
 * socket APIs; the protocol engine imports no Node modules.
 */

import net from 'net';
import tls from 'tls';
import { Buffer } from 'buffer';
import type { PeerCertificate, SmtpTransport, TlsUpgradeOptions } from '../protocol/types';

/** Options for opening a Node-backed connection. */
export interface NodeConnectOptions {
  host: string;
  port: number;
  connectTimeoutMs: number;
  /** Expected identity to validate the certificate against (host or explicit). */
  servername: string;
  tls: TlsUpgradeOptions;
}

/**
 * A forward-secret, AEAD-only cipher list (TLS 1.2 suites; TLS 1.3 suites are
 * always enabled by the stack and are all AEAD). No RC4, 3DES, CBC-only, export,
 * NULL, or anonymous suites.
 */
const SECURE_CIPHERS = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_AES_128_GCM_SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305',
  'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
].join(':');

function toMinVersion(v: string | undefined): tls.SecureVersion {
  switch (v) {
    case 'TLSv1.3':
      return 'TLSv1.3';
    case 'TLSv1.2':
    default:
      return 'TLSv1.2';
  }
}

/** Wrap a Node socket so it matches the SmtpTransport surface exactly. */
class NodeTransport implements SmtpTransport {
  constructor(private socket: net.Socket | tls.TLSSocket) {}

  write(data: string | Uint8Array, cb?: (err?: Error) => void): boolean {
    return this.socket.write(data as any, cb as any);
  }
  end(data?: string | Uint8Array, cb?: () => void): void {
    if (data === undefined) this.socket.end(cb);
    else this.socket.end(data as any, cb as any);
  }
  destroy(err?: Error): void {
    this.socket.destroy(err);
  }
  setTimeout(ms: number, cb?: () => void): void {
    this.socket.setTimeout(ms, cb);
  }
  on(event: string, h: (...args: any[]) => void): this {
    this.socket.on(event, h);
    return this;
  }
  once(event: string, h: (...args: any[]) => void): this {
    this.socket.once(event, h);
    return this;
  }
  removeListener(event: string, h: (...args: any[]) => void): this {
    this.socket.removeListener(event, h);
    return this;
  }
  removeAllListeners(event?: string): this {
    this.socket.removeAllListeners(event);
    return this;
  }

  /** STARTTLS upgrade: wrap the connected plain socket with tls.connect. */
  upgradeToTLS(opts: TlsUpgradeOptions): SmtpTransport {
    const tlsSocket = tls.connect({
      socket: this.socket as net.Socket,
      servername: opts.servername ?? opts.host,
      ca: opts.ca,
      cert: opts.cert,
      key: opts.key,
      minVersion: toMinVersion(opts.minVersion),
      ciphers: opts.ciphers ?? SECURE_CIPHERS,
      // Validation is always on. There is deliberately no option to disable it.
      rejectUnauthorized: true,
    });
    return new NodeTransport(tlsSocket);
  }

  getPeerCertificate(): PeerCertificate | undefined {
    const s = this.socket as tls.TLSSocket;
    if (typeof s.getPeerCertificate !== 'function') return undefined;
    const cert = s.getPeerCertificate(true);
    if (!cert || Object.keys(cert).length === 0) return undefined;
    return {
      fingerprint: cert.fingerprint,
      fingerprint256: cert.fingerprint256,
      pubkey: cert.pubkey ? Buffer.from(cert.pubkey).toString('base64') : undefined,
    };
  }

  getProtocol(): string | undefined {
    const s = this.socket as tls.TLSSocket;
    if (typeof s.getProtocol === 'function') {
      return s.getProtocol() ?? undefined;
    }
    return undefined;
  }
}

/** Open a plaintext connection (used for the STARTTLS path). */
export function connectPlain(opts: NodeConnectOptions): SmtpTransport {
  const socket = net.connect({ host: opts.host, port: opts.port });
  socket.setTimeout(opts.connectTimeoutMs);
  return new NodeTransport(socket);
}

/** Open an implicit-TLS connection (port 465). Emits 'secureConnect'. */
export function connectImplicitTls(opts: NodeConnectOptions): SmtpTransport {
  const socket = tls.connect({
    host: opts.host,
    port: opts.port,
    servername: opts.tls.servername ?? opts.servername,
    ca: opts.tls.ca,
    cert: opts.tls.cert,
    key: opts.tls.key,
    minVersion: toMinVersion(opts.tls.minVersion),
    ciphers: opts.tls.ciphers ?? SECURE_CIPHERS,
    rejectUnauthorized: true,
    timeout: opts.connectTimeoutMs,
  });
  return new NodeTransport(socket);
}

/** Expose the wrapper for adapters that already hold a Node socket (tests). */
export function wrapNodeSocket(socket: net.Socket | tls.TLSSocket): SmtpTransport {
  return new NodeTransport(socket);
}
