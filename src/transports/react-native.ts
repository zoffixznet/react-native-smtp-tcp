/**
 * React Native adapter over `react-native-tcp-socket`.
 *
 * This is the only file that imports the native transport. It is kept as thin as
 * possible over the verified v6.4.1 API. It cannot be executed in a Node test
 * environment (no native module), so on-device validation is a documented known
 * limitation; every other layer is proven in Node.
 *
 * Drain-before-wrap: the protocol engine asserts an empty read buffer and
 * detaches the plaintext data listener before calling {@link upgradeToTLS}. This
 * adapter's upgrade just constructs `new TLSSocket(socket, opts)` per the
 * transport's documented STARTTLS mechanism.
 */

import TcpSocket, { TLSSocket } from 'react-native-tcp-socket';
import type { TcpSocket as RnSocket } from 'react-native-tcp-socket';
import type { PeerCertificate, SmtpTransport, TlsUpgradeOptions } from '../protocol/types';
import { parseCertIdentity } from '../x509';

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

  getPeerCertificate(): PeerCertificate | undefined {
    const s = this.socket as RnSocket;
    if (typeof s.getPeerCertificate !== 'function') return undefined;
    const cert = s.getPeerCertificate();
    if (!cert) return undefined;
    const raw = cert.raw ? new Uint8Array(cert.raw) : undefined;
    // The native module returns raw DER but no parsed subjectAltName, so the
    // library parses it here to recover the identity material the on-device
    // hostname check needs. Without this, named-host identity would go
    // unverified on Android (the native socket does not check the hostname).
    let subjectAltNames: string[] | undefined;
    let commonName: string | undefined;
    if (raw) {
      const id = parseCertIdentity(raw);
      if (id) {
        subjectAltNames = id.subjectAltNames;
        commonName = id.commonName;
      }
    }
    return {
      fingerprint: cert.fingerprint,
      fingerprint256: cert.fingerprint256,
      raw,
      pubkey: cert.pubkey ? new Uint8Array(cert.pubkey) : undefined,
      subjectAltNames,
      commonName,
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
