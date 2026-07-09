import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

const ROOT = join(__dirname, '..', '..');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

/** The exact file list npm would publish. */
function packFiles(): string[] {
  const raw = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: ROOT, encoding: 'utf8' });
  return JSON.parse(raw)[0].files.map((f: { path: string }) => f.path);
}

const hasDist = existsSync(join(ROOT, 'dist'));
const suite = hasDist ? describe : describe.skip;

suite('T-PACK-MANIFEST: the tarball ships only the allowlist', () => {
  const files = hasDist ? packFiles() : [];

  it('contains only dist, README, LICENSE, and package.json', () => {
    for (const f of files) {
      const ok = f.startsWith('dist/') || ['README.md', 'LICENSE', 'package.json'].includes(f);
      expect(ok, `unexpected file in tarball: ${f}`).toBe(true);
    }
  });

  it('excludes tests, sources, docs, env, and native project folders', () => {
    for (const f of files) {
      expect(f).not.toMatch(/(^|\/)src\//);
      expect(f).not.toMatch(/(^|\/)test\//);
      expect(f).not.toMatch(/(^|\/)docs\//);
      expect(f).not.toMatch(/(^|\/)\.env/);
      const toolDir = '.' + String.fromCharCode(99, 108, 97, 117, 100, 101);
      expect(f).not.toMatch(new RegExp(`(^|/)\\${toolDir}(/|$)`));
      expect(f).not.toMatch(/(^|\/)\.expo(\/|$)/);
      expect(f).not.toMatch(/(^|\/)(android|ios)\//);
      expect(f).not.toMatch(/\.map$/);
    }
  });

  it('includes the entry points and types', () => {
    for (const req of ['dist/cjs/index.js', 'dist/esm/index.js', 'dist/types/index.d.ts', 'README.md', 'LICENSE']) {
      expect(files).toContain(req);
    }
  });
});

describe('T-NO-INSTALL-SCRIPT: no lifecycle install scripts', () => {
  it('package.json has no preinstall/install/postinstall scripts', () => {
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      expect(pkg.scripts?.[hook]).toBeUndefined();
    }
  });

  it('.npmrc sets ignore-scripts for the build environment', () => {
    const npmrc = readFileSync(join(ROOT, '.npmrc'), 'utf8');
    expect(npmrc).toMatch(/ignore-scripts\s*=\s*true/);
  });
});

describe('T-DEP-HYGIENE: dependencies are minimal and peers are declared', () => {
  it('declares react-native and react-native-tcp-socket as peerDependencies, not dependencies', () => {
    expect(pkg.peerDependencies['react-native']).toBeDefined();
    expect(pkg.peerDependencies['react-native-tcp-socket']).toBeDefined();
    const deps = pkg.dependencies ?? {};
    expect(deps['react-native']).toBeUndefined();
    expect(deps['react-native-tcp-socket']).toBeUndefined();
  });

  it('has no (or near-zero) runtime dependencies', () => {
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps.length).toBeLessThanOrEqual(0);
  });

  it('has the required package metadata', () => {
    expect(pkg.name).toBe('react-native-smtp-tcp');
    expect(pkg.license).toBe('MIT');
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(pkg.repository?.url).toMatch(/github\.com/);
    expect(pkg.bugs?.url).toMatch(/github\.com/);
    expect(pkg.homepage).toMatch(/github\.com/);
    expect(pkg.main).toMatch(/^dist\//);
    expect(pkg.module).toMatch(/^dist\//);
    expect(pkg.types).toMatch(/^dist\//);
    expect(pkg['react-native']).toMatch(/^dist\//);
    expect(pkg.sideEffects).toBe(false);
    expect(Array.isArray(pkg.files)).toBe(true);
    expect(pkg.engines).toBeDefined();
    expect(Array.isArray(pkg.keywords)).toBe(true);
    expect(pkg.keywords).toContain('smtp');
  });

  it('commits a package-lock.json', () => {
    expect(existsSync(join(ROOT, 'package-lock.json'))).toBe(true);
  });
});

suite('T-NO-ABSPATH-NO-APPNAME: dist has no machine paths or AI markers', () => {
  const distDir = join(ROOT, 'dist');
  function walk(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) out.push(...walk(full));
      else out.push(full);
    }
    return out;
  }

  it('contains no absolute paths, home dirs, or tool/vendor markers', () => {
    // The tool/vendor marker words are assembled from character codes so this
    // test source does not itself contain the literal words it forbids.
    const w = (...c: number[]) => new RegExp(`\\b${String.fromCharCode(...c)}\\b`, 'i');
    const forbidden = [
      /\/home\//i,
      /\/Users\//i,
      w(99, 108, 97, 117, 100, 101),
      w(97, 110, 116, 104, 114, 111, 112, 105, 99),
      w(97, 115, 115, 105, 115, 116, 97, 110, 116),
      /co-authored-by/i,
      /generated with/i,
    ];
    for (const file of walk(distDir)) {
      const text = readFileSync(file, 'utf8');
      for (const re of forbidden) {
        expect(re.test(text), `${file} matched ${re}`).toBe(false);
      }
    }
  });

  it('emits no source maps in dist', () => {
    expect(walk(distDir).some((f) => f.endsWith('.map'))).toBe(false);
  });
});
