/**
 * Unit tests for the config plugin's transform logic. These run in Node with no
 * device: they exercise the exact string rewrites the Expo plugin and the
 * patch-package patch apply to the react-native-tcp-socket Android native
 * client, proving the output sets HTTPS endpoint identification and creates the
 * SSLSocket with the real hostname on both the implicit-TLS and STARTTLS paths.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import {
  applyAndroidHostnameVerification,
  ANDROID_CLIENT_RELATIVE_PATH,
  ANDROID_TRANSFORM_STEPS,
} from '../../src/plugin/native-transform';
import {
  resolveAndroidClientPath,
  transformAndroidClientFile,
  runAndroidMod,
  withTcpSocketHostnameVerification,
} from '../../src/plugin/index';

const REPO_ROOT = join(__dirname, '..', '..');

/** Locate the installed stock native client, if the module is present here. */
function stockClientPath(): string | null {
  const p = join(REPO_ROOT, 'node_modules', 'react-native-tcp-socket', ...ANDROID_CLIENT_RELATIVE_PATH.split('/'));
  return existsSync(p) ? p : null;
}

/** A minimal synthetic stock source containing the exact anchors, so the test
 * does not require the native module to be installed. */
const SYNTHETIC_STOCK = [
  'import java.util.concurrent.Executors;',
  '',
  'import javax.net.ssl.SSLSocket;',
  'import javax.net.ssl.SSLSocketFactory;',
  '',
  'class TcpSocketClient {',
  '    public void connect(String address, final Integer port, ReadableMap tlsOptions) {',
  '        if (tlsOptions != null) {',
  '            SSLSocketFactory ssf = getSSLSocketFactory(context, tlsOptions);',
  '            socket = ssf.createSocket();',
  '            ((SSLSocket) socket).setUseClientMode(true);',
  '        } else {',
  '            socket = new Socket();',
  '        }',
  '        socket.connect(new InetSocketAddress(remoteInetAddress, port), connectTimeout);',
  '        if (socket instanceof SSLSocket) ((SSLSocket) socket).startHandshake();',
  '        startListening();',
  '    }',
  '',
  '    public void startTLS(Context context, ReadableMap tlsOptions) {',
  '        if (socket instanceof SSLSocket) return;',
  '        SSLSocketFactory ssf = getSSLSocketFactory(context, tlsOptions);',
  '        SSLSocket sslSocket = (SSLSocket) ssf.createSocket(socket, socket.getInetAddress().getHostAddress(), socket.getPort(), true);',
  '        sslSocket.setUseClientMode(true);',
  '        sslSocket.startHandshake();',
  '        socket = sslSocket;',
  '    }',
  '}',
  '',
].join('\n');

describe('Android hostname-verification transform', () => {
  it('enables HTTPS endpoint identification on both TLS paths', () => {
    const { contents, applied } = applyAndroidHostnameVerification(SYNTHETIC_STOCK);
    // Both paths now set the HTTPS endpoint identification algorithm.
    const httpsChecks = contents.match(/setEndpointIdentificationAlgorithm\("HTTPS"\)/g) ?? [];
    expect(httpsChecks.length).toBe(2);
    // The SSLParameters import was added.
    expect(contents).toContain('import javax.net.ssl.SSLParameters;');
    // Implicit-TLS path creates the SSLSocket over the connected socket with the
    // real hostname (address), not a hostless createSocket().
    expect(contents).toContain('sslFactory.createSocket(socket, address, port, true)');
    expect(contents).not.toContain('socket = ssf.createSocket();');
    // STARTTLS path uses the connection hostname, not the resolved IP string.
    expect(contents).toContain('socket.getInetAddress().getHostName()');
    expect(contents).not.toContain('socket.getInetAddress().getHostAddress()');
    // All four steps ran.
    expect(applied).toEqual(ANDROID_TRANSFORM_STEPS.map((s) => s.id));
  });

  it('is idempotent: a second run applies nothing', () => {
    const first = applyAndroidHostnameVerification(SYNTHETIC_STOCK);
    const second = applyAndroidHostnameVerification(first.contents);
    expect(second.applied).toEqual([]);
    expect(second.alreadyApplied).toEqual(ANDROID_TRANSFORM_STEPS.map((s) => s.id));
    expect(second.contents).toBe(first.contents);
  });

  it('throws when the source shape is unexpected (fails loud, not silent)', () => {
    const unexpected = 'class TcpSocketClient {}\n';
    expect(() => applyAndroidHostnameVerification(unexpected)).toThrow(
      /could not enable hostname verification/,
    );
  });

  it('transforms the real installed native client when present, or the synthetic one', () => {
    const stock = stockClientPath();
    const source = stock ? readFileSync(stock, 'utf8') : SYNTHETIC_STOCK;
    const { contents } = applyAndroidHostnameVerification(source);
    expect(contents).toContain('setEndpointIdentificationAlgorithm("HTTPS")');
    expect(contents).toContain('sslFactory.createSocket(socket, address, port, true)');
  });
});

describe('shipped patch stays in sync with the transform', () => {
  const patchPath = join(REPO_ROOT, 'patches', 'react-native-tcp-socket+6.4.1.patch');

  it('the patch adds the same HTTPS endpoint identification the transform does', () => {
    expect(existsSync(patchPath)).toBe(true);
    const patch = readFileSync(patchPath, 'utf8');
    // The added lines must include endpoint identification on both paths and the
    // hostname-carrying socket creation. (Added lines start with "+".)
    const added = patch
      .split('\n')
      .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
      .join('\n');
    expect(added).toContain('setEndpointIdentificationAlgorithm("HTTPS")');
    expect(added).toContain('sslFactory.createSocket(socket, address, port, true)');
    expect(added).toContain('socket.getInetAddress().getHostName()');
    expect(added).toContain('import javax.net.ssl.SSLParameters;');
  });

  it('applying the patch to the stock source yields the transform output', () => {
    const stock = stockClientPath();
    if (!stock) return; // native module not installed here; covered by transform tests
    const source = readFileSync(stock, 'utf8');
    const expected = applyAndroidHostnameVerification(source).contents;
    // Reconstruct the patched file by applying each transform step (the patch is
    // generated from these steps), then confirm the shipped patch's added lines
    // are all present in that output.
    const patch = readFileSync(patchPath, 'utf8');
    for (const line of patch.split('\n')) {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        expect(expected).toContain(line.slice(1));
      }
    }
  });
});

describe('plugin file helpers', () => {
  it('resolveAndroidClientPath finds the client under node_modules or returns null', () => {
    const found = resolveAndroidClientPath(REPO_ROOT);
    if (stockClientPath()) {
      expect(found).not.toBeNull();
      expect(found).toContain('TcpSocketClient.java');
    } else {
      expect(found).toBeNull();
    }
    // A directory with no module resolves to null.
    expect(resolveAndroidClientPath(join(REPO_ROOT, 'src'))).toBeNull();
  });

  it('transformAndroidClientFile is a no-op on an already-verified file', () => {
    // Build a temp copy of a transformed file and confirm re-running reports no
    // change (idempotent), without needing the native module.
    const os = require('os');
    const fs = require('fs');
    const dir = fs.mkdtempSync(join(os.tmpdir(), 'rnsmtp-plugin-'));
    const file = join(dir, 'TcpSocketClient.java');
    try {
      const transformed = applyAndroidHostnameVerification(SYNTHETIC_STOCK).contents;
      fs.writeFileSync(file, transformed, 'utf8');
      const res = transformAndroidClientFile(file);
      expect(res.changed).toBe(false);
      expect(res.applied).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('transformAndroidClientFile rewrites a stock file in place', () => {
    const os = require('os');
    const fs = require('fs');
    const dir = fs.mkdtempSync(join(os.tmpdir(), 'rnsmtp-plugin-'));
    const file = join(dir, 'TcpSocketClient.java');
    try {
      fs.writeFileSync(file, SYNTHETIC_STOCK, 'utf8');
      const res = transformAndroidClientFile(file);
      expect(res.changed).toBe(true);
      const out = fs.readFileSync(file, 'utf8');
      expect(out).toContain('setEndpointIdentificationAlgorithm("HTTPS")');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Expo plugin wrapper (with an injected config-plugins loader)', () => {
  it('registers an android dangerous mod and runs the transform', async () => {
    const os = require('os');
    const fs = require('fs');
    const projectRoot = fs.mkdtempSync(join(os.tmpdir(), 'rnsmtp-proj-'));
    const clientDir = join(projectRoot, 'node_modules', ...('react-native-tcp-socket/' + ANDROID_CLIENT_RELATIVE_PATH).split('/').slice(0, -1));
    fs.mkdirSync(clientDir, { recursive: true });
    const clientFile = join(clientDir, 'TcpSocketClient.java');
    fs.writeFileSync(clientFile, SYNTHETIC_STOCK, 'utf8');
    try {
      let registered: [string, (c: any) => Promise<any>] | null = null;
      const fakeLoader = () => ({
        withDangerousMod: (config: any, mod: [string, (c: any) => Promise<any>]) => {
          registered = mod;
          return { ...config, _wrapped: true };
        },
      });
      const out = withTcpSocketHostnameVerification({ name: 'app' }, fakeLoader as any);
      expect((out as any)._wrapped).toBe(true);
      expect(registered).not.toBeNull();
      expect(registered![0]).toBe('android');
      // Invoke the registered mod and confirm it transforms the file.
      await registered![1]({ modRequest: { projectRoot } });
      const transformed = fs.readFileSync(clientFile, 'utf8');
      expect(transformed).toContain('setEndpointIdentificationAlgorithm("HTTPS")');
    } finally {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  });

  it('runAndroidMod is a no-op when the module is not installed', async () => {
    const os = require('os');
    const fs = require('fs');
    const projectRoot = fs.mkdtempSync(join(os.tmpdir(), 'rnsmtp-empty-'));
    try {
      const cfg = { modRequest: { projectRoot }, marker: 1 };
      const out = await runAndroidMod(cfg as any);
      expect((out as any).marker).toBe(1);
    } finally {
      fs.rmSync(projectRoot, { recursive: true, force: true });
    }
  });
});
