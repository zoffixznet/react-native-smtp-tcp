/**
 * Drives a FakeSocket by watching what the client writes and pushing scripted
 * server replies in response. A step is matched against the most recent write.
 */

import { Buffer } from 'buffer';
import { FakeSocket } from './fake-socket';

export interface Step {
  /** Substring or regex the written command must match to trigger this step. */
  when: string | RegExp;
  /** Bytes to send back, or a function returning them. */
  reply: string | ((written: string) => string);
  /** Optional side effect (e.g. destroy the socket) instead of / after reply. */
  then?: (sock: FakeSocket) => void;
  /** Only fire once. */
  once?: boolean;
}

/**
 * Attach a scripted responder to a fake socket. It inspects each write and, when
 * a step matches, sends the reply. Returns a controller to inspect progress.
 */
export function driveFake(sock: FakeSocket, steps: Step[]): { firedCount: number } {
  const state = { firedCount: 0 };
  const used = new Set<number>();

  arm(sock);

  function arm(target: FakeSocket): void {
    let lastLen = 0;
    const originalWrite = target.write.bind(target);
    target.write = (data: string | Uint8Array, cb?: (err?: Error) => void): boolean => {
      const ret = originalWrite(data, cb);
      queueMicrotask(() => {
        const full = target.writtenText();
        const fresh = full.slice(lastLen);
        lastLen = full.length;
        if (fresh.length === 0) return;
        for (let i = 0; i < steps.length; i++) {
          if (used.has(i)) continue;
          const step = steps[i];
          const matched =
            typeof step.when === 'string' ? fresh.includes(step.when) : step.when.test(fresh);
          if (matched) {
            if (step.once) used.add(i);
            state.firedCount++;
            const reply = typeof step.reply === 'function' ? step.reply(fresh) : step.reply;
            if (reply) target.serverSend(reply);
            if (step.then) step.then(target);
            break;
          }
        }
      });
      return ret;
    };

    // Follow a TLS upgrade so the same script drives the wrapped socket.
    const originalUpgrade = target.upgradeToTLS.bind(target);
    target.upgradeToTLS = (opts) => {
      const next = originalUpgrade(opts) as FakeSocket;
      arm(next);
      return next;
    };
  }

  return state;
}

/** Concatenate a greeting push helper. */
export function pushGreeting(sock: FakeSocket, greeting = '220 test.local ESMTP\r\n'): void {
  queueMicrotask(() => sock.serverSend(greeting));
}

export function toText(buf: Buffer): string {
  return buf.toString('utf8');
}
