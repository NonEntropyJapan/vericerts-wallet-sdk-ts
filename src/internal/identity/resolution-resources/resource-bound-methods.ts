import { MAX_DOCUMENT_BYTES } from '../../http/body-limit.js';
import type { DIDDocument } from '../did.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import type { Resolver } from '../resolver.js';
import type { ResolveDidWebDeps } from '../web/did-web-cache.js';
import { MethodWeb, NO_DID_WEB_CACHE } from '../web/method-web.js';
import { MethodWebVh } from '../webvh/method-webvh.js';
import { createWebVhAttemptLedger, resolveDidWebVhHooked } from '../webvh/resolve.js';
import type { InflightByteReservations } from './inflight-byte-reservations.js';

class WitnessReservationUnavailable extends Error {}

class ResourceBoundWeb extends MethodWeb {
  constructor(
    private readonly reservations: InflightByteReservations,
    deps?: ResolveDidWebDeps,
  ) {
    super(deps);
  }

  override resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    return this.reservations.run(MAX_DOCUMENT_BYTES, () => super.resolve(did, scope));
  }
}

class ResourceBoundWebVh extends MethodWebVh {
  constructor(private readonly reservations: InflightByteReservations) {
    super();
  }

  override async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    // Only the two attempts of this resolve share credit; concurrent resolves never share it.
    const ledger = createWebVhAttemptLedger();
    try {
      return await this.reservations.run(MAX_DOCUMENT_BYTES, async () => {
        let releaseWitness: (() => void) | undefined;
        try {
          return await resolveDidWebVhHooked(did, scope, {
            ledger,
            beforeWitnessFile: () => {
              releaseWitness = this.reservations.tryReserve(MAX_DOCUMENT_BYTES);
              if (releaseWitness === undefined) throw new WitnessReservationUnavailable();
            },
          });
        } finally {
          releaseWitness?.();
        }
      });
    } catch (error) {
      if (!(error instanceof WitnessReservationUnavailable)) throw error;
    }
    // The first reservation has already been released before queueing the atomic retry.
    return this.reservations.run(2 * MAX_DOCUMENT_BYTES, () =>
      resolveDidWebVhHooked(did, scope, { ledger }),
    );
  }
}

/** SDK-internal registration; private webvh hooks never become consumer dependencies. */
export function registerResourceBoundWebMethods(
  resolver: Resolver,
  reservations: InflightByteReservations,
): void {
  resolver.register(new ResourceBoundWeb(reservations));
  resolver.registerUncached(new ResourceBoundWeb(reservations, { cache: NO_DID_WEB_CACHE }));
  resolver.register(new ResourceBoundWebVh(reservations));
}
