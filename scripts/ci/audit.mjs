import { spawnSync } from 'node:child_process';
import { isMainModule } from '../lib/is-main-module.mjs';
import { cleanEnvironment } from './environment.mjs';

export function parseCriticalAdvisories(stdout) {
  const parsed = stdout.trim() === '' ? {} : JSON.parse(stdout);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error('Invalid audit report');
  const findings = [];
  for (const [pkgName, advisories] of Object.entries(parsed)) {
    if (!Array.isArray(advisories)) throw new Error('Invalid audit advisory list');
    for (const advisory of advisories) {
      if (!advisory || !['info', 'low', 'moderate', 'high', 'critical'].includes(advisory.severity))
        throw new Error('Invalid audit advisory severity');
      if (advisory.severity === 'critical') findings.push({ pkgName, ...advisory });
    }
  }
  return findings;
}

export function audit(cwd, spawn = spawnSync) {
  const result = spawn('bun', ['audit', '--json'], {
    cwd,
    env: cleanEnvironment(),
    encoding: 'utf8',
  });
  if (result.error || result.signal || ![0, 1].includes(result.status))
    throw new Error('SDK dependency audit failed');
  const text = result.stdout ?? '';
  if (!text.trim() && result.status !== 0)
    throw new Error('SDK dependency audit returned no report');
  const findings = parseCriticalAdvisories(text);
  console.log(`SDK dependency advisory report: ${text.trim() || '{}'}`);
  if (findings.length)
    throw new Error(
      `Critical SDK advisories: ${findings.map((x) => `${x.pkgName}: ${x.url}`).join(', ')}`,
    );
  console.log('SDK dependency audit: no Critical advisories');
}
if (isMainModule(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('SDK audit takes no options');
  audit(process.cwd());
}
