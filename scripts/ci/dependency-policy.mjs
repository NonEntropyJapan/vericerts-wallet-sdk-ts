import { semver } from '../lib/load-semver.mjs';
import { peerFixtureOverride } from './sphereon-fixture-policy.mjs';

const FIELDS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const canonicalName = (name) =>
  typeof name === 'string' &&
  name.length <= 214 &&
  packageName.test(name) &&
  !['node_modules', 'favicon.ico'].includes(name);
const tag = /^[A-Za-z][A-Za-z0-9._-]*$/;
function registryRange(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    if (semver.validRange(value) !== null) {
      const range = new semver.Range(value);
      return range.set.every((alternative) =>
        alternative.some((comparator) => comparator.value !== ''),
      );
    }
  } catch {
    return false;
  }
  // Deliberate registry-only tag subset; archive filenames are npm file specs.
  return tag.test(value) && !/\.(?:tgz|tar(?:\.gz)?|zip)$/i.test(value);
}
function registrySpec(name, value) {
  if (!canonicalName(name) || typeof value !== 'string') return false;
  if (!value.startsWith('npm:')) return registryRange(value);
  const target = value.slice(4);
  const at = target.lastIndexOf('@');
  return at > 0 && canonicalName(target.slice(0, at)) && registryRange(target.slice(at + 1));
}
function selectorName(selector) {
  if (canonicalName(selector)) return selector;
  const at = selector.lastIndexOf('@');
  return at > 0 && canonicalName(selector.slice(0, at)) && registryRange(selector.slice(at + 1))
    ? selector.slice(0, at)
    : null;
}

export function dependencyProblems(pkg, context) {
  const problems = [];
  const direct = new Map();
  const report = (at) => problems.push(`nonregistry or unsupported dependency ${at}`);
  const fixtureOverride = peerFixtureOverride(pkg, context);
  if (fixtureOverride === null) problems.push('Sphereon peer fixture override or lock changed');
  for (const field of FIELDS) {
    if (pkg[field] === undefined) continue;
    if (!object(pkg[field])) {
      report(field);
      continue;
    }
    for (const [name, value] of Object.entries(pkg[field])) {
      if (!registrySpec(name, value)) report(`${field}.${name}`);
      direct.set(name, value);
    }
  }
  function replacement(value, at, name, allowReference) {
    if (typeof value === 'string') {
      if (at === fixtureOverride?.at && value === fixtureOverride.value) return;
      if (value.startsWith('$')) {
        const ref = value.slice(1);
        // References select a direct declaration, never another replacement.
        if (!allowReference || !direct.has(ref) || !registrySpec(ref, direct.get(ref))) report(at);
      } else if (!registrySpec(name, value)) report(at);
      return;
    }
    if (!object(value) || !Object.keys(value).length) {
      report(at);
      return;
    }
    for (const [selector, child] of Object.entries(value)) {
      const target =
        selector === '.' && !['overrides', 'resolutions', 'pnpm.overrides'].includes(at)
          ? name
          : selectorName(selector);
      if (!target) report(`${at}.${selector}`);
      replacement(child, `${at}.${selector}`, target ?? 'invalid', allowReference);
    }
  }
  for (const field of ['overrides', 'resolutions'])
    if (pkg[field] !== undefined) {
      if (!object(pkg[field])) report(field);
      else replacement(pkg[field], field, pkg.name ?? 'sdk-policy', field === 'overrides');
    }
  if (pkg.pnpm !== undefined) {
    if (!object(pkg.pnpm)) report('pnpm');
    else {
      if (pkg.pnpm.overrides !== undefined)
        replacement(pkg.pnpm.overrides, 'pnpm.overrides', pkg.name ?? 'sdk-policy', true);
      if (pkg.pnpm.packageExtensions !== undefined) {
        if (!object(pkg.pnpm.packageExtensions)) report('pnpm.packageExtensions');
        else
          for (const [selector, extension] of Object.entries(pkg.pnpm.packageExtensions)) {
            if (!selectorName(selector) || !object(extension))
              report(`pnpm.packageExtensions.${selector}`);
            else
              problems.push(
                ...dependencyProblems(extension).map(
                  (message) => `pnpm.packageExtensions.${selector}: ${message}`,
                ),
              );
          }
      }
      for (const field of ['catalog', 'catalogs'])
        if (pkg.pnpm[field] !== undefined) report(`pnpm.${field}`);
    }
  }
  for (const field of [
    'workspaces',
    'catalog',
    'catalogs',
    'bundleDependencies',
    'bundledDependencies',
  ])
    if (pkg[field] !== undefined) report(field);
  return problems;
}
