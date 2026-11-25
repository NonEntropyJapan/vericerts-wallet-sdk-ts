/** Public-only declaration consumer, appended to each existing strict module-mode fixture. */
export function didResourcesTypeFixture(packageName) {
  return `
import {
  createDidResolutionResources as makeDidResources,
  createDidResolver as makeResourceResolver,
  type DidResolutionResources,
  type DidResolverOptions as ResourceResolverOptions,
  type Resolver as ResourceResolver,
} from '${packageName}/identity';
import {
  createDidResolutionResources as makeRootDidResources,
  type DidResolutionResources as RootDidResources,
} from '${packageName}';
type ResourceEqual<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type ResourceAssert<T extends true> = T;
type ResourceContracts = [
  ResourceAssert<ResourceEqual<Parameters<typeof makeDidResources>[0], { readonly maxInflightBytes: number }>>,
  ResourceAssert<ResourceEqual<DidResolutionResources, RootDidResources>>,
  ResourceAssert<ResourceEqual<Extract<keyof DidResolutionResources, string>, never>>,
];
const resourceHandle: DidResolutionResources = makeDidResources({ maxInflightBytes: 4 * 1024 * 1024 });
const rootResourceHandle: RootDidResources = makeRootDidResources({ maxInflightBytes: 2 * 1024 * 1024 });
const resourceResolverFactory: (
  opts?: ResourceResolverOptions,
  resources?: { readonly webResolutionResources?: DidResolutionResources },
) => ResourceResolver = makeResourceResolver;
resourceResolverFactory(undefined, { webResolutionResources: resourceHandle });
resourceResolverFactory({}, { webResolutionResources: rootResourceHandle });
// @ts-expect-error opaque handles cannot be constructed structurally
const forgedDidResources: DidResolutionResources = {};
// @ts-expect-error no reservation operation is public
resourceHandle.run(1, async () => undefined);
// @ts-expect-error no reservation upgrade operation is public
resourceHandle.tryReserve(1);
// @ts-expect-error no mutable reservation state is public
resourceHandle.reserved = 0;
// @ts-expect-error the capacity is required
makeDidResources({});
// @ts-expect-error the obsolete option name is not public
makeResourceResolver({}, { httpResources: resourceHandle });
void forgedDidResources;
export type { ResourceContracts };
`;
}
