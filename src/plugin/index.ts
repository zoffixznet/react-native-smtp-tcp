/**
 * Expo config plugin that enables TLS certificate chain and hostname
 * verification in the react-native-tcp-socket Android native transport during
 * `expo prebuild`.
 *
 * Consumers add a single entry to their app config `plugins` array:
 *
 *   { "plugins": ["react-native-smtp-tcp"] }
 *
 * During prebuild the plugin rewrites the installed react-native-tcp-socket
 * `TcpSocketClient.java` so the implicit-TLS (465) and STARTTLS (587) paths both
 * create the SSLSocket with the real hostname and set the HTTPS endpoint
 * identification algorithm before the handshake. The native handshake then
 * rejects a certificate whose SAN/CN does not match the configured host.
 *
 * The transform logic lives in `./native-transform` and is unit-tested in Node.
 * This file is the thin Expo wrapper around it. `@expo/config-plugins` is a
 * consumer dependency (part of the Expo toolchain); it is required lazily and
 * typed loosely so this package does not take a hard dependency on it.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  ANDROID_CLIENT_RELATIVE_PATH,
  applyAndroidHostnameVerification,
} from './native-transform';

/** Minimal shape of the Expo config object the plugin receives and returns. */
interface ExpoConfig {
  [key: string]: unknown;
}

/** Minimal shape of the mod props Expo passes to a dangerous mod. */
interface DangerousModProps {
  modRequest: { projectRoot: string };
}

/** Minimal surface of `@expo/config-plugins` this plugin uses. */
interface ConfigPluginsModule {
  withDangerousMod: (
    config: ExpoConfig,
    mod: [string, (cfg: ExpoConfig & DangerousModProps) => Promise<ExpoConfig>],
  ) => ExpoConfig;
}

/**
 * Resolve the installed react-native-tcp-socket native client file from the
 * consumer's project root. Returns null when the module or file is not present
 * (nothing to patch).
 */
export function resolveAndroidClientPath(projectRoot: string): string | null {
  const candidate = path.join(
    projectRoot,
    'node_modules',
    'react-native-tcp-socket',
    ...ANDROID_CLIENT_RELATIVE_PATH.split('/'),
  );
  return fs.existsSync(candidate) ? candidate : null;
}

/**
 * Read the native client file, apply the transform, and write it back if it
 * changed. Returns a short status for logging/testing. Exported for unit tests.
 */
export function transformAndroidClientFile(clientPath: string): {
  changed: boolean;
  applied: string[];
  alreadyApplied: string[];
} {
  const source = fs.readFileSync(clientPath, 'utf8');
  const result = applyAndroidHostnameVerification(source);
  if (result.applied.length > 0) {
    fs.writeFileSync(clientPath, result.contents, 'utf8');
  }
  return {
    changed: result.applied.length > 0,
    applied: result.applied,
    alreadyApplied: result.alreadyApplied,
  };
}

/** Load @expo/config-plugins from the consumer's project (lazy, optional). */
function loadConfigPlugins(): ConfigPluginsModule {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('@expo/config-plugins') as ConfigPluginsModule;
}

/**
 * The mod callback run during prebuild: locate the installed native client and
 * transform it in place. Exported so it can be unit-tested without Expo.
 */
export async function runAndroidMod(cfg: ExpoConfig & DangerousModProps): Promise<ExpoConfig> {
  const clientPath = resolveAndroidClientPath(cfg.modRequest.projectRoot);
  if (clientPath) {
    transformAndroidClientFile(clientPath);
  }
  return cfg;
}

/**
 * The Expo config plugin entry point. Wraps the app config so that, during
 * prebuild, the Android native client is transformed to verify the hostname.
 * `load` is injectable so the wrapper can be unit-tested without Expo installed.
 */
export function withTcpSocketHostnameVerification(
  config: ExpoConfig,
  load: () => ConfigPluginsModule = loadConfigPlugins,
): ExpoConfig {
  const { withDangerousMod } = load();
  return withDangerousMod(config, ['android', runAndroidMod]);
}

export default withTcpSocketHostnameVerification;
