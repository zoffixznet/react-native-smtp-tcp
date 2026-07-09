/**
 * Minimal ambient declaration for the `react-native-tcp-socket` peer dependency
 * so this library type-checks and builds without the native module installed in
 * this environment. The real module provides these at runtime on device. Only
 * the parts this adapter uses are declared.
 */
declare module 'react-native-tcp-socket' {
  export interface TcpSocket {
    write(data: string | Uint8Array, encoding?: unknown, cb?: (err?: Error) => void): boolean;
    end(data?: string | Uint8Array, encoding?: unknown): void;
    destroy(): void;
    setTimeout(ms: number, cb?: () => void): void;
    setNoDelay(noDelay?: boolean): void;
    on(event: string, listener: (...args: any[]) => void): TcpSocket;
    once(event: string, listener: (...args: any[]) => void): TcpSocket;
    removeListener(event: string, listener: (...args: any[]) => void): TcpSocket;
    removeAllListeners(event?: string): TcpSocket;
    getPeerCertificate?(): any;
    _id?: number;
    pending?: boolean;
    connecting?: boolean;
  }

  export interface TlsSocketOptions {
    ca?: string;
    cert?: string;
    key?: string;
    androidKeyStore?: string;
    certAlias?: string;
    keyAlias?: string;
  }

  export interface ConnectionOptions {
    port: number;
    host?: string;
    connectTimeout?: number;
  }

  export class TLSSocket implements TcpSocket {
    constructor(socket: TcpSocket, options?: TlsSocketOptions);
    write(data: string | Uint8Array, encoding?: unknown, cb?: (err?: Error) => void): boolean;
    end(data?: string | Uint8Array, encoding?: unknown): void;
    destroy(): void;
    setTimeout(ms: number, cb?: () => void): void;
    setNoDelay(noDelay?: boolean): void;
    on(event: string, listener: (...args: any[]) => void): TcpSocket;
    once(event: string, listener: (...args: any[]) => void): TcpSocket;
    removeListener(event: string, listener: (...args: any[]) => void): TcpSocket;
    removeAllListeners(event?: string): TcpSocket;
    getPeerCertificate(): any;
  }

  export function connectTLS(
    options: ConnectionOptions & TlsSocketOptions,
    callback?: () => void,
  ): TLSSocket;

  export function createConnection(
    options: ConnectionOptions,
    callback?: () => void,
  ): TcpSocket;

  const _default: {
    connectTLS: typeof connectTLS;
    createConnection: typeof createConnection;
    TLSSocket: typeof TLSSocket;
  };
  export default _default;
}
