// Read-only. Never print configuration, account identities, keys or certificates.
import {readFileSync} from 'node:fs';
import {X509Certificate, createPrivateKey} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {dirname, join} from 'node:path';

try {
  const [packageRoot, configPath] = process.argv.slice(2);
  const {leafCovers, mitmHosts} = await import(pathToFileURL(join(packageRoot, 'src/mitm.js')));
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  const directory = dirname(configPath);
  const caPem = readFileSync(join(directory, 'teamclaude-ca.pem'), 'utf8');
  const leafPem = readFileSync(join(directory, 'teamclaude-leaf.pem'), 'utf8');
  const leaf = new X509Certificate(leafPem);
  const ca = new X509Certificate(caPem);
  const key = createPrivateKey(readFileSync(join(directory, 'teamclaude-leaf.key')));
  if (!leafCovers(caPem, leafPem, mitmHosts(config)) || !leaf.checkPrivateKey(key)
      || Date.parse(ca.validFrom) > Date.now() || Date.parse(leaf.validFrom) > Date.now()) {
    throw new Error('certificate preflight refused');
  }
} catch {
  process.stderr.write('teamclaude certificate preflight refused; inspect privately\n');
  process.exitCode = 1;
}
