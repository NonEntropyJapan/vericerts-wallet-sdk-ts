import { MAX_DOCUMENT_BYTES } from '../../http/body-limit.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { InflightByteReservations } from './inflight-byte-reservations.js';

declare const didResolutionResourcesBrand: unique symbol;

/**
 * Opaque in-process reservations shared by DID web resolvers; create with the factory.
 * Not serializable. Pre-1.0 maturity follows the identity entry's implicit experimental policy.
 */
export interface DidResolutionResources {
  readonly [didResolutionResourcesBrand]: true;
}

const handles = new WeakMap<object, InflightByteReservations>();

function isOptions(value: unknown): value is object {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Share concurrent did:web/webvh body reservations across resolver instances.
 * This does not limit other DID methods or all SDK HTTP. Capacity must be a finite safe
 * integer of at least 2 MiB; there is no implicit 4 MiB default.
 * @throws TypeError for malformed options, RangeError for an invalid numeric capacity.
 */
export function createDidResolutionResources(options: {
  readonly maxInflightBytes: number;
}): DidResolutionResources {
  if (!isOptions(options)) throw new TypeError('Invalid DID resolution resource options');
  const capacity = ownProperty<unknown>(options, 'maxInflightBytes');
  if (typeof capacity !== 'number') throw new TypeError('DID capacity must be an own number');
  if (!Number.isSafeInteger(capacity) || capacity < 2 * MAX_DOCUMENT_BYTES) {
    throw new RangeError('DID capacity must be a safe integer of at least 2 MiB');
  }
  const handle = Object.freeze(Object.create(null)) as DidResolutionResources;
  handles.set(handle, new InflightByteReservations(capacity));
  return handle;
}

/** Validate new resolver options without exposing a reservation operation or accepting copies. */
export function readDidResolutionResources(
  resources: unknown,
): InflightByteReservations | undefined {
  if (resources === undefined) return undefined;
  if (!isOptions(resources)) throw new TypeError('Invalid DID resolver resources');
  if (!Object.hasOwn(resources, 'webResolutionResources')) {
    if ('webResolutionResources' in resources) {
      throw new TypeError('DID resolution resources must be an own option');
    }
    return undefined;
  }
  const handle = ownProperty<unknown>(resources, 'webResolutionResources');
  if (handle === undefined) return undefined;
  const budget = isOptions(handle) ? handles.get(handle) : undefined;
  if (budget === undefined) throw new TypeError('Invalid DID resolution resource handle');
  return budget;
}
