/**
 * A TransportFactory backed by an in-memory FakeSocket for index-level tests
 * that need a scripted server without a real socket. Used for cases like the
 * SMTPUTF8 gate where the server capability set must be controlled precisely.
 */

import type { TransportFactory } from '../../src/index';
import { FakeSocket } from './fake-socket';
import { driveFake } from './fake-driver';

/** EHLO capabilities without SMTPUTF8. */
const EHLO_NO_UTF8 = '250-test.local\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n';

function scripted(): FakeSocket {
  // The handshake is authoritative for chain + hostname, so no certificate
  // fields are needed here; the client authenticates over the completed secure
  // connection (no pin configured).
  const sock = new FakeSocket();
  queueMicrotask(() => {
    sock.fireSecureConnect();
    sock.serverSend('220 test.local ESMTP\r\n');
  });
  driveFake(sock, [
    { when: /^EHLO /m, reply: EHLO_NO_UTF8, once: true },
    { when: /^AUTH PLAIN /m, reply: '235 ok\r\n', once: true },
    { when: /^MAIL FROM:/m, reply: '250 ok\r\n', once: true },
    { when: /^RCPT TO:/m, reply: '250 ok\r\n', once: true },
    { when: /^DATA/m, reply: '354 go\r\n', once: true },
    { when: /\r\n\.\r\n/, reply: '250 2.0.0 Queued\r\n', once: true },
    { when: /^QUIT/m, reply: '221 bye\r\n', once: true },
  ]);
  return sock;
}

export function fakeFactoryWithoutSmtpUtf8(): TransportFactory {
  return {
    connectImplicitTls() {
      return scripted();
    },
    connectPlain() {
      return scripted();
    },
  };
}
