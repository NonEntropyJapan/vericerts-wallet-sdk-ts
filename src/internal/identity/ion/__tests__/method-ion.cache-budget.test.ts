import { expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import { createResolutionWorkBudget } from '../../resolution-budget.js';
import { MethodIon } from '../method-ion.js';
import { ionResponse, makeIonCreate, NODE_URL } from './ion.fixtures.js';

it('did:ion のキャッシュ命中も呼び出しスコープの本文量に計上する', async () => {
  const create = makeIonCreate();
  const response = ionResponse(create.shortForm, create);
  const weight = JSON.stringify(response).length;
  const { fetchFn, calls } = recordingFetch(() => jsonReply(response));
  const method = new MethodIon({ nodeUrl: NODE_URL, fetchFn });
  await method.resolve(create.shortForm);

  const scope = createResolutionWorkBudget(undefined, weight);
  expect((await method.resolve(create.shortForm, scope)).id).toBe(create.shortForm);
  expect(scope.remainingBodyLength).toBe(0);
  await expectRejects(
    method.resolve(create.shortForm, scope),
    ErrorCodes.INVALID_DID,
    'resolution_work_limit',
  );
  expect(calls).toHaveLength(1);
});
