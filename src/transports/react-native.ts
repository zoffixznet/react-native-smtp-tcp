/**
 * React Native adapter over `react-native-tcp-socket`.
 *
 * This is the only file that imports the native transport. It is kept as thin as
 * possible over the v6.4.1 API. It cannot be executed in a Node test environment
 * (no native module), so on-device behavior is validated on a real device by the
 * consuming app; every other layer runs in Node.
 *
 * The native transport verifies the certificate chain and, once the shipped
 * config plugin / patch is applied at build time, the hostname. This adapter
 * therefore relies on a correct native handshake and only exposes the peer
 * certificate for the optional certificate-fingerprint pin.
 *
 * Drain-before-wrap: the protocol engine asserts an empty read buffer and
 * detaches the plaintext data listener before calling {@link upgradeToTLS}. This
 * adapter's upgrade just constructs `new TLSSocket(socket, opts)` per the
 * transport's STARTTLS mechanism.
 */

import TcpSocket, { TLSSocket } from 'react-native-tcp-socket';
import type { TcpSocket as RnSocket } from 'react-native-tcp-socket';
import type { PeerCertificate, SmtpTransport, TlsUpgradeOptions } from '../protocol/types';

/** Options for opening a device connection. */
export interface RnConnectOptions {
  host: string;
  port: number;
  connectTimeoutMs: number;
  tls: TlsUpgradeOptions;
}

class RnTransport implements SmtpTransport {
  constructor(private socket: RnSocket) {}

  write(data: string | Uint8Array, cb?: (err?: Error) => void): boolean {
    return this.socket.write(data, undefined, cb);
  }
  end(data?: string | Uint8Array): void {
    this.socket.end(data);
  }
  destroy(): void {
    this.socket.destroy();
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

  /**
   * STARTTLS upgrade in place. The native TLSSocket constructor reuses the
   * same socket id and starts TLS synchronously; the caller has already ensured
   * the plaintext buffer is empty and detached its data listener.
   */
  upgradeToTLS(opts: TlsUpgradeOptions): SmtpTransport {
    // react-native-tcp-socket accepts only ca/cert/key here; there is no public
    // servername/min-version/cipher knob, so those are governed by the platform
    // TLS stack. This is documented in the README.
    const tlsSocket = new TLSSocket(this.socket, {
      ca: opts.ca,
      cert: opts.cert,
      key: opts.key,
    });
    return new RnTransport(tlsSocket as unknown as RnSocket);
  }

  /**
   * Fetch the peer certificate for the optional pin check. The native module
   * resolves this asynchronously, so it is awaited. The returned shape carries
   * only the fingerprints and the base64 public key the pin needs; hostname
   * identity is enforced by the native handshake, not here.
   */
  async getPeerCertificate(): Promise<PeerCertificate | undefined> {
    const s = this.socket as RnSocket;
    if (typeof s.getPeerCertificate !== 'function') return undefined;
    const cert = await s.getPeerCertificate();
    if (!cert || typeof cert !== 'object') return undefined;
    return {
      fingerprint: typeof cert.fingerprint === 'string' ? cert.fingerprint : undefined,
      fingerprint256: typeof cert.fingerprint256 === 'string' ? cert.fingerprint256 : undefined,
      pubkey: typeof cert.pubkey === 'string' ? cert.pubkey : undefined,
    };
  }

  /**
   * Best-effort negotiated TLS protocol version. The native TLSSocket exposes
   * getProtocol() post-handshake on platforms that support it; when it is
   * unavailable this returns undefined and the engine's floor check is a no-op.
   */
  getProtocol(): string | undefined {
    const s = this.socket as RnSocket;
    if (typeof s.getProtocol !== 'function') return undefined;
    const v = s.getProtocol();
    return v ?? undefined;
  }
}

/**
 * Implicit-TLS connect (port 465). Returns a transport that emits
 * 'secureConnect' when TCP+TLS is ready, per the transport's connectTLS.
 */
export function connectImplicitTls(opts: RnConnectOptions): SmtpTransport {
  const socket = TcpSocket.connectTLS({
    port: opts.port,
    host: opts.host,
    connectTimeout: opts.connectTimeoutMs,
    ca: opts.tls.ca,
    cert: opts.tls.cert,
    key: opts.tls.key,
  });
  return new RnTransport(socket as unknown as RnSocket);
}

/** Open a plaintext connection (used for the STARTTLS path). */
export function connectPlain(opts: RnConnectOptions): SmtpTransport {
  const socket = TcpSocket.createConnection({
    port: opts.port,
    host: opts.host,
    connectTimeout: opts.connectTimeoutMs,
  });
  return new RnTransport(socket);
}
