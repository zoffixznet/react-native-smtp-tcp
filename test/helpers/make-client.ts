/**
 * Helper to construct an SmtpClient over a given transport with test defaults.
 */

import { SmtpClient } from '../../src/protocol/client';
import type { ClientOptions } from '../../src/protocol/client';
import { DEFAULT_CAPS, DEFAULT_TIMEOUTS } from '../../src/protocol/caps';
import type { SmtpTransport } from '../../src/protocol/types';

export function makeClient(
  transport: SmtpTransport,
  overrides: Partial<ClientOptions> = {},
): SmtpClient {
  const opts: ClientOptions = {
    host: 'test.local',
    clientId: '[127.0.0.1]',
    secure: 'starttls',
    requireTLS: true,
    caps: DEFAULT_CAPS,
    timeouts: DEFAULT_TIMEOUTS,
    tlsUpgradeOptions: { host: 'test.local', servername: 'test.local' },
    verifyTlsChannel: () => {
      /* accept by default in tests that do not care about identity */
    },
    ...overrides,
  };
  return new SmtpClient(transport, opts);
}
