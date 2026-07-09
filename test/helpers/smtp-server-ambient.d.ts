/** Minimal ambient types for `smtp-server` used only by the test suite. */
declare module 'smtp-server' {
  import type { Server } from 'net';
  import type { Readable } from 'stream';

  export interface SMTPServerAuth {
    method: string;
    username?: string;
    password?: string;
    accessToken?: string;
  }
  export interface SMTPServerAddress {
    address: string;
  }
  export interface SMTPServerSession {
    envelope: {
      mailFrom: SMTPServerAddress | false;
      rcptTo: SMTPServerAddress[];
    };
  }
  export interface SMTPServerOptions {
    secure?: boolean;
    authOptional?: boolean;
    disabledCommands?: string[];
    hideSTARTTLS?: boolean;
    authMethods?: string[];
    key?: string;
    cert?: string;
    ca?: string[];
    minVersion?: string;
    maxVersion?: string;
    ciphers?: string;
    logger?: boolean;
    onAuth?(
      auth: SMTPServerAuth,
      session: SMTPServerSession,
      callback: (err: Error | null, response?: { user?: string }) => void,
    ): void;
    onData?(
      stream: Readable,
      session: SMTPServerSession,
      callback: (err?: Error) => void,
    ): void;
  }

  export class SMTPServer {
    constructor(options: SMTPServerOptions);
    server: Server;
    listen(port: number, host: string, cb?: () => void): void;
    close(cb?: () => void): void;
    on(event: string, listener: (...args: any[]) => void): void;
    once(event: string, listener: (...args: any[]) => void): void;
  }
}
