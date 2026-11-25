/**
 * `Wallet.receiveCredential` が `opts` から内部ファサードの依存（`ReceiveCredentialDeps`）を組み立てる処理。
 *
 * `{ ...opts }` による複製は own かつ列挙可能なプロパティしか写さないため、クラスインスタンスの
 * プロトタイプメソッド（`authorize` / `createDpopProof` / `verifyReceived`）と継承した `fetchImpl` が落ち、
 * DPoP なしの Bearer やグローバル `fetch` へ**無言で**倒れていた（fail-open）。ここでは複製せず、
 * キーごとに 1 回だけ読む。読み方の規則はファサード（`facade/deps.ts`）と同じで、`Object.prototype` 由来の
 * 値の拒否（`rejectPollutedReceiveDeps`）もファサードと同じ関数を使う。
 * `Wallet` は拒否を `resolveActiveHolder` の前（副作用・通信の前）で行うため、`receive.ts` からも呼ぶ。
 */

import type { ReceiveCredentialDeps } from '../../internal/auth/index.js';
import type { RECEIVE_DEPS_KEYS } from '../../internal/auth/oid4vci/facade/deps.js';
import { resolveInjectedFetch } from '../../internal/fetch-di.js';
import {
  nonObjectPrototypeProperty,
  ownProperty,
} from '../../internal/prototype-safety/own-property.js';

/**
 * 全キーを own プロパティとして持つ依存（値が `undefined` のキーも載せる）。
 *
 * 全キーを own にしておくと、ファサードが `nonObjectPrototypeProperty` / `ownProperty` で読むとき
 * 記述子の最初の保持者が常にこのオブジェクト自身になり、プロトタイプ鎖（`Object.prototype`）へ到達しない。
 * キーは {@link RECEIVE_DEPS_KEYS}（`ReceiveCredentialDeps` の全キーと型で一致）から作るため、リテラルでの書き漏れはコンパイルエラーになる。
 */
type CompleteReceiveDeps = {
  readonly [K in (typeof RECEIVE_DEPS_KEYS)[number]]: ReceiveCredentialDeps[K] | undefined;
};

/**
 * 関数 DI（`authorize` / `createDpopProof` / `fetchImpl`）を 1 回だけ読み、元の `opts` を `this` に束縛して返す。
 *
 * プロトタイプメソッド・継承した関数は正当な DI なので `nonObjectPrototypeProperty` で読む。
 * 関数でない値はそのまま返し、型の検査はファサード（`8010`。`fetchImpl` は未指定扱い）に任せる。
 * **グローバル `fetch` そのものには束縛しない**（ブラウザで `Illegal invocation` になり `3004` に化けるため。
 * `internal/fetch-di.ts`）。
 */
function readBoundFunction<K extends 'authorize' | 'createDpopProof' | 'fetchImpl'>(
  opts: object,
  key: K,
): ReceiveCredentialDeps[K] {
  const raw = nonObjectPrototypeProperty<unknown>(opts, key);
  if (typeof raw !== 'function') {
    return raw as ReceiveCredentialDeps[K];
  }
  // グローバル `fetch` を束縛しない規則は `resolveInjectedFetch` の 1 か所に任せる（receiver が無ければ束縛しない）。
  if (key === 'fetchImpl' && resolveInjectedFetch({ fetchImpl: raw }).receiver === undefined) {
    return raw as ReceiveCredentialDeps[K];
  }
  return raw.bind(opts) as ReceiveCredentialDeps[K];
}

/** 純データ DI を own 限定で読む（クラスのプロトタイプ値は採用しない）。値の検証はファサードが行う。 */
function readData<K extends keyof ReceiveCredentialDeps>(
  opts: object,
  key: K,
): ReceiveCredentialDeps[K] | undefined {
  return ownProperty<ReceiveCredentialDeps[K]>(opts, key);
}

/**
 * `opts` を複製せずに、ファサード向けの依存を組み立てる。
 *
 * - `signer` / `holderDid` / `keyId` は `opts` から読まず、渡された Wallet の解決値で常に上書きする。
 * - `verifyReceived` は呼び出し側が `readVerifyReceived` の 1 回の読みから得た値（判定と実行を同じ読みに揃える）。
 * - 関数 DI は元の `opts` を `this` に束縛、純データは own 限定（{@link readBoundFunction} / {@link readData}）。
 * - 戻り値は全キーを own に持つ素のオブジェクトリテラル（{@link CompleteReceiveDeps}）。
 *
 * 事前に `rejectPollutedReceiveDeps`（`facade/deps.ts`）を通しておくこと。
 */
export function buildReceiveDeps(
  opts: object | undefined,
  resolved: Pick<ReceiveCredentialDeps, 'signer' | 'holderDid' | 'keyId'>,
  verifyReceived: ReceiveCredentialDeps['verifyReceived'],
): ReceiveCredentialDeps {
  const source = opts ?? {};
  const deps: CompleteReceiveDeps = {
    signer: resolved.signer,
    holderDid: resolved.holderDid,
    keyId: resolved.keyId,
    authorize: readBoundFunction(source, 'authorize'),
    createDpopProof: readBoundFunction(source, 'createDpopProof'),
    verifyReceived,
    fetchImpl: readBoundFunction(source, 'fetchImpl'),
    txCode: readData(source, 'txCode'),
    clientAssertion: readData(source, 'clientAssertion'),
    clientAssertionType: readData(source, 'clientAssertionType'),
    clientId: readData(source, 'clientId'),
    redirectUri: readData(source, 'redirectUri'),
    format: readData(source, 'format'),
    credentialRequestVersion: readData(source, 'credentialRequestVersion'),
    correlationContext: readData(source, 'correlationContext'),
  };
  return deps as ReceiveCredentialDeps;
}
