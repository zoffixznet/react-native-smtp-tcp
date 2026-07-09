// Post-build fixups:
// 1. Write a package.json into dist/cjs (commonjs) and dist/esm (module) so Node
//    resolves each build correctly regardless of the root package "type".
// 2. Rewrite relative import/export specifiers in the ESM output to include the
//    ".js" extension, which Node's ESM loader requires. The TypeScript sources
//    use extensionless specifiers (clean for readers and bundler-friendly); this
//    step makes the emitted ESM spec-compliant for plain Node consumers.
import { writeFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const cjsDir = join(root, 'dist', 'cjs');
const esmDir = join(root, 'dist', 'esm');

for (const [dir, type] of [
  [cjsDir, 'commonjs'],
  [esmDir, 'module'],
]) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ type }, null, 2) + '\n');
}

// Rewrite ESM specifiers.
const SPEC_RE = /(\bfrom\s*|\bimport\s*)(['"])(\.\.?\/[^'"]*?)(['"])/g;
const DYN_RE = /(\bimport\(\s*)(['"])(\.\.?\/[^'"]*?)(['"]\s*\))/g;

function addExt(spec, fileDir) {
  if (spec.endsWith('.js') || spec.endsWith('.json') || spec.endsWith('.mjs')) return spec;
  // If the specifier resolves to a directory, point at its index.js.
  const abs = join(fileDir, spec);
  if (existsSync(abs) && statSync(abs).isDirectory()) {
    return spec.replace(/\/?$/, '/index.js');
  }
  return spec + '.js';
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      walk(full);
    } else if (entry.endsWith('.js')) {
      let src = readFileSync(full, 'utf8');
      src = src.replace(SPEC_RE, (_m, kw, q1, spec, q2) => `${kw}${q1}${addExt(spec, dir)}${q2}`);
      src = src.replace(DYN_RE, (_m, kw, q1, spec, q2) => `${kw}${q1}${addExt(spec, dir)}${q2}`);
      writeFileSync(full, src);
    }
  }
}

if (existsSync(esmDir)) walk(esmDir);

console.log('wrote dist/{cjs,esm}/package.json and fixed ESM import extensions');
