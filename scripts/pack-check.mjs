// Verify the publish tarball's file list is exactly the allowlist, then run the
// leak/secret scan over the tarball and dist/. Fails on any deviation. This is
// the CI-style publishing safety gate. It never runs `npm publish`.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();

if (!existsSync(join(root, 'dist'))) {
  console.error('dist/ does not exist; run `npm run build` first.');
  process.exit(2);
}

// 1. Get the exact file list npm would publish.
const raw = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: root, encoding: 'utf8' });
const parsed = JSON.parse(raw);
const files = parsed[0].files.map((f) => f.path).sort();

// 2. Assert every shipped path is inside the allowlist (dist/, README, LICENSE).
const allowedTop = new Set(['README.md', 'LICENSE', 'package.json']);
const violations = [];
for (const f of files) {
  const top = f.split('/')[0];
  const inDist = f.startsWith('dist/');
  if (!inDist && !allowedTop.has(f)) {
    violations.push(f);
  }
  // Explicitly forbid known-sensitive paths even if a future files entry widens.
  if (
    /(^|\/)\.env/.test(f) ||
    /(^|\/)\.claude(\/|$)/.test(f) ||
    /(^|\/)\.expo(\/|$)/.test(f) ||
    /(^|\/)(test|tests)\//.test(f) ||
    /(^|\/)(android|ios)\//.test(f) ||
    /(^|\/)src\//.test(f) ||
    /\.map$/.test(f) ||
    /(^|\/)docs\//.test(f)
  ) {
    violations.push(f);
  }
  void top;
}

if (violations.length > 0) {
  console.error('pack-check: the tarball contains files outside the allowlist:');
  for (const v of [...new Set(violations)]) console.error(`  ${v}`);
  process.exit(1);
}

// 3. Assert the essentials are present.
const required = ['README.md', 'LICENSE', 'package.json', 'dist/cjs/index.js', 'dist/esm/index.js', 'dist/types/index.d.ts'];
const missing = required.filter((r) => !files.includes(r));
if (missing.length > 0) {
  console.error('pack-check: the tarball is missing required files:');
  for (const m of missing) console.error(`  ${m}`);
  process.exit(1);
}

// 4. Assert there are no lifecycle install scripts in the published manifest.
const pkg = JSON.parse(execFileSync('node', ['-e', 'process.stdout.write(require("fs").readFileSync("package.json","utf8"))'], { cwd: root, encoding: 'utf8' }));
for (const hook of ['preinstall', 'install', 'postinstall']) {
  if (pkg.scripts && pkg.scripts[hook]) {
    console.error(`pack-check: package.json defines a forbidden ${hook} script.`);
    process.exit(1);
  }
}

console.log(`pack-check: tarball file list OK (${files.length} files, allowlist respected).`);
for (const f of files) console.log(`  ${f}`);

// 5. Run the leak/secret scan over the tarball and dist/.
execFileSync('node', [join(root, 'scripts', 'leak-scan.mjs')], { cwd: root, stdio: 'inherit' });

console.log('pack-check: passed.');
