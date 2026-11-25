/**
 * detectController は ethr の `fetchEvents`（registry.ts）を共有するため、応答ログの検証が
 * 委任経路にも効く: 別 registry の address・別 identity のログで owner を差し替えられない。
 */

import { describe, expect, test } from 'bun:test';
import { zeroPadValue } from 'ethers';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  CHAIN_ID,
  IDENTITY,
  OWNER,
  ownerLog,
  RPC_URL,
  rpcStub,
} from '../../../identity/ethr/__tests__/rpc-stub.js';
import { createEthersEventSource } from '../../../identity/ethr/registry.js';
import { parseEthrDid } from '../../did-ethr.js';
import { detectController } from '../../events.js';

const START = parseEthrDid(`did:ethr:${IDENTITY}`);
const FOREIGN_REGISTRY = '0x3333333333333333333333333333333333333333';
const OTHER_IDENTITY = '0x2222222222222222222222222222222222222222';

/** START の identity を引かれたときだけ `owner` を返す（連鎖の次段・別 DID の照会にはログ無し）。 */
function sourceReturning(owner: unknown[]) {
  const startTopic = zeroPadValue(IDENTITY, 32).toLowerCase();
  const { fetchImpl } = rpcStub({
    owner: (identityTopic) => (identityTopic.toLowerCase() === startTopic ? owner : []),
  });
  return createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
}

describe('detectController: 応答ログの検証', () => {
  test('正当なログでは owner を controller として解決する（対照）', async () => {
    const controller = await detectController(START, sourceReturning([ownerLog(OWNER, 5, 0)]));
    expect(controller).toBe(`did:ethr:${OWNER}`);
  });

  test.each([
    ['別 registry の address', { ...ownerLog(OWNER, 5, 0), address: FOREIGN_REGISTRY }],
    ['別 identity の topics[1]', ownerLog(OWNER, 5, 0, OTHER_IDENTITY)],
  ])('%s のログは DID_NOT_FOUND（controller を差し替えられない）', async (_label, log) => {
    const error = await detectController(START, sourceReturning([log])).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_NOT_FOUND);
  });
});
