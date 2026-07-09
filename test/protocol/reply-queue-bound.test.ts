import { describe, it, expect } from 'vitest';
import { FakeSocket } from '../helpers/fake-socket';
import { driveFake } from '../helpers/fake-driver';
import { makeClient } from '../helpers/make-client';
import { DEFAULT_CAPS } from '../../src/protocol/caps';
import { SmtpConnectionError, SmtpProtocolError } from '../../src/protocol/errors';
import type { SmtpClient } from '../../src/protocol/client';

const EHLO = '250-test.local\r\n250 SMTPUTF8\r\n';

function startImplicit(sock: FakeSocket): void {
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  driveFake(sock, [{ when: /^EHLO /m, reply: EHLO, once: true }]);
}

/** Read the private replyQueue length without changing production types. */
function queueLength(client: SmtpClient): number {
  return (client as unknown as { replyQueue: unknown[] }).replyQueue.length;
}

describe('SEC: unsolicited-reply queue is bounded (no OOM)', () => {
  it('fails closed instead of buffering unbounded replies across data events', async () => {
    const sock = new FakeSocket();
    startImplicit(sock);
    // Small cap so the test is fast; the mechanism is identical at any cap.
    const cap = 4;
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      caps: { ...DEFAULT_CAPS, maxQueuedReplies: cap },
    });
    await client.connect();

    // No command is pending now. A hostile server delivers many small, complete,
    // well-formed final replies, EACH as its own data event (its own push), so
    // the per-reply parser caps reset between them and never bound the queue.
    // The client must fail closed once the queue exceeds its cap, not grow it.
    let maxSeen = 0;
    for (let i = 0; i < 10_000 && !sock.destroyed; i++) {
      sock.serverSend('250 unsolicited\r\n');
      maxSeen = Math.max(maxSeen, queueLength(client));
    }

    // The connection was torn down (fail closed) well before 10k replies.
    expect(sock.destroyed).toBe(true);
    // The queue never grew past the cap; memory is bounded.
    expect(maxSeen).toBeLessThanOrEqual(cap);
    expect(queueLength(client)).toBeLessThanOrEqual(cap);

    // A subsequent command rejects with the stored fail-closed error explaining
    // that the server sent excess unsolicited replies.
    await expect(
      client.sendTransaction({
        from: 'me@example.com',
        to: ['you@example.com'],
        data: 'Subject: x\r\n\r\nbody\r\n',
        sizeBytes: 20,
        smtpUtf8: false,
        eightBitMime: false,
      }),
    ).rejects.toBeInstanceOf(SmtpProtocolError);
    void SmtpConnectionError;

    client.close();
  });

  it('a single un-consumed reply within the cap is still delivered to the next waiter', async () => {
    // The narrow legitimate case (a reply arriving just before a consumer arms)
    // must still work: one queued reply is delivered, not treated as an abort.
    const sock = new FakeSocket();
    startImplicit(sock);
    driveFake(sock, [
      { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
      { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
      { when: /^DATA/m, reply: '354 go\r\n', once: true },
      { when: /\r\n\.\r\n/, reply: '250 2.0.0 Queued\r\n', once: true },
    ]);
    const client = makeClient(sock, {
      secure: 'implicit',
      requireTLS: true,
      caps: { ...DEFAULT_CAPS, maxQueuedReplies: 4 },
    });
    await client.connect();
    const res = await client.sendTransaction({
      from: 'me@example.com',
      to: ['you@example.com'],
      data: 'Subject: x\r\n\r\nbody\r\n',
      sizeBytes: 20,
      smtpUtf8: false,
      eightBitMime: false,
    });
    expect(res.accepted).toEqual(['you@example.com']);
    void SmtpProtocolError;
    client.close();
  });
});
