// Exercise qScan's real scanner and v1 producer from a pinned sibling checkout.
// Built dist is used in CI. Node 24 can execute sources offline in local review.
import { registerHooks } from 'node:module';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const root = resolve(process.env.QSCAN_ROOT);
const built = existsSync(resolve(root, 'packages/core/dist/crypto-agility.js'));
if (!built) {
  registerHooks({ resolve(specifier, context, next) {
    if (specifier.endsWith('.js') && context.parentURL?.startsWith('file:')) {
      const url = new URL(specifier.slice(0, -3) + '.ts', context.parentURL);
      if (existsSync(fileURLToPath(url))) return { url: url.href, shortCircuit: true };
    }
    return next(specifier, context);
  } });
}
const entry = name => pathToFileURL(resolve(root, 'packages/core', built ? 'dist' : 'src', name + (built ? '.js' : '.ts'))).href;
const { scan } = await import(entry('scan'));
const { buildCryptoAgilityManifest } = await import(entry('crypto-agility'));
const result = await scan({ root: resolve('tests/fixtures/qscan-project') });
if (result.findings.length < 1) throw new Error('qScan did not detect fixture RSA');
// Explicit stable producer inputs: location normalization does not change findings.
result.root = '.';
const manifest = buildCryptoAgilityManifest(result, {
  generatedAt: '2026-10-11T00:00:00Z', repository: 'quantakrypto/test-fixture',
  commit: '1'.repeat(40), hybridKexInUse: true,
});
process.stdout.write(JSON.stringify(manifest, null, 2) + '\n');
