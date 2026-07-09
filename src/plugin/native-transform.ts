/**
 * Source transform that enables TLS certificate chain AND hostname verification
 * in the react-native-tcp-socket Android native transport.
 *
 * Stock react-native-tcp-socket v6.4.1 validates the certificate chain (via the
 * default trust manager) but never enables endpoint identification, and it
 * creates the client SSLSocket without an associated hostname:
 *
 *   - the implicit-TLS `connect` path calls `ssf.createSocket()` (no host) and
 *     connects it to the resolved IP, so the socket has no peer hostname for
 *     verification, and
 *   - the STARTTLS `startTLS` path layers TLS using the resolved IP string
 *     (`socket.getInetAddress().getHostAddress()`) instead of the hostname.
 *
 * In both paths `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` is
 * never set, so the handshake accepts any certificate whose chain is trusted,
 * regardless of the hostname.
 *
 * This transform rewrites `TcpSocketClient.java` so both paths create the
 * SSLSocket bound to the real hostname and set the HTTPS endpoint identification
 * algorithm before the handshake. The JDK/Conscrypt trust manager then rejects a
 * certificate whose SAN/CN does not match the configured host, exactly as the
 * Node reference path does.
 *
 * The transform is expressed as a list of anchored, idempotent string
 * replacements against the stock v6.4.1 source, so it is deterministic and can
 * be unit-tested in Node without a device. If an anchor is not found (a future
 * version changed the source), {@link applyAndroidHostnameVerification} reports
 * it so the build fails loudly instead of silently leaving verification off.
 */

/** A single anchored replacement. */
export interface TransformStep {
  /** A short id used in diagnostics. */
  id: string;
  /** The exact stock substring to replace (must be unique in the file). */
  find: string;
  /** The replacement substring. */
  replace: string;
  /**
   * A marker that, when already present, means this step was applied before.
   * Used to make the transform idempotent (running prebuild twice is safe).
   */
  appliedMarker: string;
}

/** The relative path (from the module root) of the file this transform edits. */
export const ANDROID_CLIENT_RELATIVE_PATH =
  'android/src/main/java/com/asterinet/react/tcpsocket/TcpSocketClient.java';

/**
 * The ordered transform steps for TcpSocketClient.java (stock v6.4.1).
 *
 * Step 1 replaces the implicit-TLS socket creation so the SSLSocket is created
 * with the real hostname and endpoint identification is enabled.
 *
 * Step 2 replaces the STARTTLS layering so it uses the connection host and
 * enables endpoint identification.
 */
export const ANDROID_TRANSFORM_STEPS: TransformStep[] = [
  {
    id: 'add-sslparameters-import',
    find: 'import javax.net.ssl.SSLSocket;\nimport javax.net.ssl.SSLSocketFactory;',
    replace:
      'import javax.net.ssl.SSLParameters;\n' +
      'import javax.net.ssl.SSLSocket;\n' +
      'import javax.net.ssl.SSLSocketFactory;',
    appliedMarker: 'import javax.net.ssl.SSLParameters;',
  },
  {
    id: 'implicit-tls-hostname',
    find:
      '        if (tlsOptions != null) {\n' +
      '            SSLSocketFactory ssf = getSSLSocketFactory(context, tlsOptions);\n' +
      '            socket = ssf.createSocket();\n' +
      '            ((SSLSocket) socket).setUseClientMode(true);\n' +
      '        } else {\n' +
      '            socket = new Socket();\n' +
      '        }',
    replace:
      '        SSLSocketFactory sslFactory = null;\n' +
      '        if (tlsOptions != null) {\n' +
      '            sslFactory = getSSLSocketFactory(context, tlsOptions);\n' +
      '            socket = new Socket();\n' +
      '        } else {\n' +
      '            socket = new Socket();\n' +
      '        }',
    appliedMarker: 'SSLSocketFactory sslFactory = null;',
  },
  {
    id: 'implicit-tls-wrap-and-verify',
    find: '        if (socket instanceof SSLSocket) ((SSLSocket) socket).startHandshake();\n',
    replace:
      '        if (sslFactory != null) {\n' +
      '            // Layer TLS over the connected plain socket using the real\n' +
      '            // hostname so endpoint identification can verify the certificate\n' +
      '            // against the SAN/CN, and enable the HTTPS identification\n' +
      '            // algorithm before the handshake.\n' +
      '            SSLSocket sslSocket = (SSLSocket) sslFactory.createSocket(socket, address, port, true);\n' +
      '            sslSocket.setUseClientMode(true);\n' +
      '            SSLParameters sslParams = sslSocket.getSSLParameters();\n' +
      '            sslParams.setEndpointIdentificationAlgorithm("HTTPS");\n' +
      '            sslSocket.setSSLParameters(sslParams);\n' +
      '            sslSocket.startHandshake();\n' +
      '            socket = sslSocket;\n' +
      '        }\n',
    appliedMarker: 'sslParams.setEndpointIdentificationAlgorithm("HTTPS");',
  },
  {
    id: 'starttls-hostname',
    find:
      '        SSLSocketFactory ssf = getSSLSocketFactory(context, tlsOptions);\n' +
      '        SSLSocket sslSocket = (SSLSocket) ssf.createSocket(socket, socket.getInetAddress().getHostAddress(), socket.getPort(), true);\n' +
      '        sslSocket.setUseClientMode(true);\n' +
      '        sslSocket.startHandshake();\n' +
      '        socket = sslSocket;',
    replace:
      '        SSLSocketFactory ssf = getSSLSocketFactory(context, tlsOptions);\n' +
      '        SSLSocket sslSocket = (SSLSocket) ssf.createSocket(socket, socket.getInetAddress().getHostName(), socket.getPort(), true);\n' +
      '        sslSocket.setUseClientMode(true);\n' +
      '        SSLParameters startTlsParams = sslSocket.getSSLParameters();\n' +
      '        startTlsParams.setEndpointIdentificationAlgorithm("HTTPS");\n' +
      '        sslSocket.setSSLParameters(startTlsParams);\n' +
      '        sslSocket.startHandshake();\n' +
      '        socket = sslSocket;',
    appliedMarker: 'startTlsParams.setEndpointIdentificationAlgorithm("HTTPS");',
  },
];

/** Result of running the transform. */
export interface TransformResult {
  /** The transformed source. */
  contents: string;
  /** Ids of steps that were applied in this run. */
  applied: string[];
  /** Ids of steps that were already present (idempotent no-ops). */
  alreadyApplied: string[];
}

/**
 * Apply the Android hostname-verification transform to the given source.
 *
 * Each step is idempotent: if its applied marker is already present the step is
 * skipped. If a step's anchor is missing AND its marker is absent, the source
 * shape is unexpected and an error is thrown so the caller can fail the build
 * rather than silently ship a client that does not verify the hostname.
 */
export function applyAndroidHostnameVerification(source: string): TransformResult {
  let contents = source;
  const applied: string[] = [];
  const alreadyApplied: string[] = [];

  for (const step of ANDROID_TRANSFORM_STEPS) {
    if (contents.includes(step.appliedMarker)) {
      alreadyApplied.push(step.id);
      continue;
    }
    if (!contents.includes(step.find)) {
      throw new Error(
        `react-native-smtp-tcp: could not enable hostname verification: the ` +
          `react-native-tcp-socket source did not match the expected shape at ` +
          `step "${step.id}". The installed version may be unsupported.`,
      );
    }
    contents = contents.replace(step.find, step.replace);
    applied.push(step.id);
  }

  return { contents, applied, alreadyApplied };
}
