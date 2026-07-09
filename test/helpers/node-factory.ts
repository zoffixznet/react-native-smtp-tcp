/**
 * A TransportFactory backed by the Node net/tls adapter, injected into
 * createTransport so the whole public API is exercised against real sockets.
 */

import type { TransportFactory } from '../../src/index';
import {
  connectImplicitTls as nodeConnectImplicit,
  connectPlain as nodeConnectPlain,
} from '../../src/transports/node';

export const nodeFactory: TransportFactory = {
  connectPlain(config, tls) {
    return nodeConnectPlain({
      host: config.host,
      port: config.port,
      connectTimeoutMs: config.timeouts.connectMs,
      servername: config.servername,
      tls,
    });
  },
  connectImplicitTls(config, tls) {
    return nodeConnectImplicit({
      host: config.host,
      port: config.port,
      connectTimeoutMs: config.timeouts.connectMs,
      servername: config.servername,
      tls,
    });
  },
};
