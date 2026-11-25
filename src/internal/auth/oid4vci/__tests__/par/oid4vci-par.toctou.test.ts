/**
 * `pushAuthorizationRequest` の必須フィールドを「ガードと送出で二重に読まない」こと（TOCTOU）。
 *
 * `PARRequest` は plain object に限らず、`get par_endpoint() {…}` のようにアクセサでメンバを
 * 公開するクラスインスタンスでもよい（`own-property.ts`「どちらのヘルパーを使うか」）。その形を
 * 受理する以上、**同じフィールドを 2 回読むと 1 回目と 2 回目で別の値が返り得る**。
 *
 * - `par_endpoint`: 1 回目 `https://…` で HTTPS ガードを通し、2 回目 `http://攻撃者` を送信先に
 *   されると、`client_assertion`（`<WUA>~<WUA-PoP>`）を載せた body が平文で攻撃者へ渡る。
 * - `state`: CSRF 防止の照合値が、検査した値と実際に送った値でずれる。
 * - `code_challenge`: PKCE の結び付きが、検査した値と実際に送った値でずれる。
 *
 * いずれも「冒頭で 1 回だけ読み、ガードと送出でそのローカルだけを使う」ことで塞ぐ。必須フィールド
 * なので `ownProperty`（own 限定）には**しない**（own 限定にすると上記のクラス実装が壊れる）。
 */

import { describe, expect, it } from 'bun:test';
import type { PARRequest } from '../../par/index.js';
import { pushAuthorizationRequest } from '../../par/index.js';
import {
  type FetchCall,
  PAR_ENDPOINT,
  STATE,
  stubFetchOk,
  VALID_PAR_BODY,
  WALLET_ATTESTATION_ASSERTION_TYPE,
  WALLET_ATTESTATION_CLIENT_ASSERTION,
} from './par-fixtures.js';

const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const REDIRECT_URI = 'com.example.wallet://cb';

/** 2 回目以降の読み取りで攻撃者の値へ差し替わるエンドポイント / パラメータ。 */
const ATTACKER_ENDPOINT = 'http://attacker.example.com/par';
const ATTACKER_STATE = 'attacker-chosen-state';
const ATTACKER_CODE_CHALLENGE = 'attacker-chosen-code-challenge';

/** 読み取り回数を数え、2 回目以降に別の値を返すアクセサを持つ `PARRequest` を作る。 */
function requestWithAlternatingField(
  field: 'par_endpoint' | 'state' | 'code_challenge',
  second: string,
  calls: FetchCall[],
): PARRequest {
  const source: Record<string, unknown> = {
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: CODE_CHALLENGE,
    redirect_uri: REDIRECT_URI,
    state: STATE,
    client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
    client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
    fetchImpl: stubFetchOk(VALID_PAR_BODY, calls),
  };
  const first = source[field] as string;
  let reads = 0;
  Object.defineProperty(source, field, {
    configurable: true,
    enumerable: true,
    get(): string {
      reads += 1;
      return reads === 1 ? first : second;
    },
  });
  return source as unknown as PARRequest;
}

describe('pushAuthorizationRequest: ガードと送出で必須フィールドを読み直さない', () => {
  it('HTTPS ガード通過後に par_endpoint が差し替わっても攻撃者ホストへ送らない', async () => {
    const calls: FetchCall[] = [];
    const req = requestWithAlternatingField('par_endpoint', ATTACKER_ENDPOINT, calls);

    await pushAuthorizationRequest(req);

    expect(calls).toHaveLength(1);
    // 検査した URL と実際の送信先が一致していること（攻撃者ホストへは出ない）。
    expect(calls[0]?.url).toBe(PAR_ENDPOINT);
    expect(calls[0]?.url).not.toBe(ATTACKER_ENDPOINT);
    // client_assertion（`<WUA>~<WUA-PoP>`）が平文で攻撃者へ渡っていないことを併せて固定する。
    expect(calls[0]?.body.get('client_assertion')).toBe(WALLET_ATTESTATION_CLIENT_ASSERTION);
  });

  it('空値ガード通過後に state が差し替わっても検査した値を送る', async () => {
    const calls: FetchCall[] = [];
    const req = requestWithAlternatingField('state', ATTACKER_STATE, calls);

    await pushAuthorizationRequest(req);

    expect(calls[0]?.body.get('state')).toBe(STATE);
  });

  it('空値ガード通過後に code_challenge が差し替わっても検査した値を送る', async () => {
    const calls: FetchCall[] = [];
    const req = requestWithAlternatingField('code_challenge', ATTACKER_CODE_CHALLENGE, calls);

    await pushAuthorizationRequest(req);

    expect(calls[0]?.body.get('code_challenge')).toBe(CODE_CHALLENGE);
  });
});
