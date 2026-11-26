const npmName = (component) => [component?.group, component?.name].filter(Boolean).join('/');

export function prepareSdkBom(generated, pkg, lockedPackages, lockPath) {
  // cdxgen 12.8.4 の CycloneDX 1.5 evidence は bun.lock の絶対パスを記録する。
  const bom = JSON.parse(generated, (_key, value) => (value === lockPath ? 'bun.lock' : value));
  const sdk = bom.metadata?.component;
  const rootDeps = bom.dependencies?.find((dep) => dep.ref === sdk?.['bom-ref']);
  if (
    npmName(sdk) !== pkg.name ||
    sdk.version !== pkg.version ||
    !sdk.licenses?.some((entry) => entry.license?.id === pkg.license) ||
    !bom.components?.length ||
    !rootDeps?.dependsOn?.length ||
    bom.components.some((component) => !component.licenses?.length)
  ) {
    throw new Error(
      'Incomplete SDK SBOM: check package identity, dependencies and license metadata',
    );
  }
  sdk.type = 'library';
  // cdxgen の Bun lockfile 読み取りでは、SDK の optional peer は成分表だけに載る。
  for (const name of Object.keys(pkg.peerDependencies ?? {})) {
    const descriptor = lockedPackages[name]?.[0];
    const peer = bom.components.find(
      (component) => `${npmName(component)}@${component.version}` === descriptor,
    );
    if (!peer) throw new Error(`Missing locked peer in SDK SBOM: ${name}`);
    if (!rootDeps.dependsOn.includes(peer['bom-ref'])) rootDeps.dependsOn.push(peer['bom-ref']);
  }
  rootDeps.dependsOn.sort();
  return bom;
}
