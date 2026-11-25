/**
 * PAR が送る `client_assertion` の形式の回帰テスト。
 *
 * PAR と Token Request の両方で同じ client assertion 形式 `<WUA>~<WUA-PoP>` を使う。
 *
 * すなわち唯一の生成箇所である `buildClientAttestation`（`internal/eudi/wua/proof.ts`）が組み立てた
 * 連結形が PAR body へそのまま（`~` 区切りを保ち WUA JWT 部・PoP 部の両方を残して）送出され、
 * PAR 経路専用の変換・分解・切り出しが入り込まないことを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { makeWuaJwt, wscdSigner } from '../../../../eudi/wua/__tests__/wua-fixtures.js';
import { buildClientAttestation, buildWuaProofOfPossession } from '../../../../eudi/wua/proof.js';
import { parseWalletUnitAttestation } from '../../../../eudi/wua/wua.js';
import { pushAuthorizationRequest } from '../../par/index.js';
import {
  baseRequest,
  type FetchCall,
  PAR_ENDPOINT,
  stubFetchOk,
  VALID_PAR_BODY,
  WALLET_ATTESTATION_ASSERTION_TYPE,
} from './par-fixtures.js';

/** WUA を署名する Wallet Provider 相当の鍵（`proof.test.ts` と同値）。 */
const PROVIDER_KEY = new Uint8Array(32).fill(3);

/** WUA-PoP の `iat` を固定するための基準時刻。 */
const NOW = 1_712_400_000;

describe('PAR は buildClientAttestation の <WUA>~<WUA-PoP> をそのまま送る', () => {
  it('client_assertion は WUA JWT 部と PoP 部を `~` で連結したまま body に載る', async () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const pop = buildWuaProofOfPossession(
      wua,
      { aud: PAR_ENDPOINT, nonce: 'c_nonce_123', jti: '9f3c1f0e-6a52-4f8e-9b2d-7c1a5d3e4b10' },
      wscdSigner(),
      NOW,
    );
    const attestation = buildClientAttestation(wua, pop);

    const calls: FetchCall[] = [];
    await pushAuthorizationRequest({
      ...baseRequest(stubFetchOk(VALID_PAR_BODY, calls)),
      client_assertion: attestation.clientAssertion,
      client_assertion_type: attestation.clientAssertionType,
    });

    const sent = calls[0]?.body.get('client_assertion');
    // Token Request 経路が使う値と 1 文字も違わないこと。
    expect(sent).toBe(`${wua.jwt}~${pop}`);
    // 連結形が保たれている（PoP 単独へ切り詰められていない）こと。
    expect(sent?.split('~')).toEqual([wua.jwt, pop]);
    expect(calls[0]?.body.get('client_assertion_type')).toBe(WALLET_ATTESTATION_ASSERTION_TYPE);
    expect(attestation.clientAssertionType).toBe(WALLET_ATTESTATION_ASSERTION_TYPE);
  });
});
