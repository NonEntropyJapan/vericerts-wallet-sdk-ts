/**
 * Wallet ファサードの `receiveCredential` の実装。
 *
 * `ops.ts`（VC / VP / SD-JWT の発行・検証）から分離した独立ファイル。契約の詳細は
 * `wallet/credential/api.ts` の `PresentationApi.receiveCredential` の JSDoc を参照。
 */

import type { ReceivedVerifiableCredential } from '../../internal/auth/index.js';
import { receiveCredential as receiveCredentialImpl } from '../../internal/auth/index.js';
import { rejectPollutedReceiveDeps } from '../../internal/auth/oid4vci/facade/deps.js';
import type { KeyManager } from '../../internal/keymanager/keymanager.js';
import type { PersonaManager } from '../../internal/persona/persona.js';
import {
  type ReceivedIssuerTrust,
  readVerifyReceived,
  verifyReceivedCredential,
} from '../issuer-trust/index.js';
import { type ActiveSignerOptions, resolveActiveHolder } from '../setup.js';
import type { ReceiveCredentialOptions } from './api.js';
import { buildReceiveDeps } from './receive-deps.js';

/**
 * OID4VCI で Credential Offer から VC を受領する。
 *
 * アクティブペルソナから署名鍵・Holder DID・検証鍵 ID を解決し（`resolveActiveHolder`。
 * `EudiFacade.receivePID` と経路を共有）、`opts` と合わせて内部ファサード `receiveCredential` へ
 * 委譲する。`markExperimental` 未ラップの素の実装を直接呼ぶため、`Wallet.receiveCredential` は
 * ランタイム警告を出さない。
 *
 * **受領した VC の署名は既定で検証する**（挙動変更・後方非互換）。検証を
 * **`Wallet` メソッド層に置く**のは、`Wallet` が既に `this.resolver` を持つ一方で、内部ファサード
 * （`internal/auth/oid4vci/facade/receive.ts`）は DID 解決の依存を意図的に持たないためである
 * （同ファイルのヘッダコメント）。したがって `@deprecated` のモジュール関数版は従来どおり
 * `deps.verifyReceived` 指定時のみ検証する。
 *
 * **`opts.verifyReceived` を指定した場合は既定検証を「置換」する（併用しない）。** 指定時の検証は
 * 内部ファサードが実行済みであり、そこへ既定検証を重ねると、`x5c` / Trust Anchor など DID 以外の
 * 鍵解決を持ち込む正当な呼び出しが DID 解決の失敗で拒否されてしまう。指定の有無・実行する値は
 * どちらも {@link readVerifyReceived}（`wallet/issuer-trust/received-signature.ts`）の**同じ 1 回の読み**から
 * 得る（判定と実行の読みを分けない。同関数の JSDoc 参照）。
 *
 * **`opts` は複製せず（`{ ...opts }` は own プロパティしか写さず、クラスインスタンスのプロトタイプメソッドを
 * 落とす）、キーごとに 1 回だけ読む**（`receive-deps.ts`）。関数 DI（`authorize` /
 * `createDpopProof` / `verifyReceived` / `fetchImpl`）はプロトタイプメソッド・継承でも採用し、元の `opts` を
 * `this` に束縛して呼ぶ（グローバル `fetch` そのものには束縛しない）。純データ DI は own 限定で、
 * クラスのプロトタイプ値は採用しない。`signer` / `holderDid` / `keyId` は `opts` で上書きできない。
 * `ReceiveCredentialDeps` の 15 キーのいずれかが `Object.prototype` 由来（汚染）のときは、ファサード
 * と同じく `8010` / `invalid_receive_deps` で**拒否**する（`Wallet` は `resolveActiveHolder` の前）。
 */
export async function receiveCredentialWith(
  personas: PersonaManager,
  keymanager: KeyManager,
  issuerTrust: ReceivedIssuerTrust,
  offerURI: string,
  opts?: ReceiveCredentialOptions,
  signing?: ActiveSignerOptions,
): Promise<ReceivedVerifiableCredential> {
  rejectPollutedReceiveDeps(opts);
  const { signer, did, keyId } = await resolveActiveHolder(personas, keymanager, signing);
  const { hasCustomVerify, verifyReceived } = readVerifyReceived(opts);
  const deps = buildReceiveDeps(opts, { signer, holderDid: did, keyId }, verifyReceived);
  const received = await receiveCredentialImpl(offerURI, deps);
  if (!hasCustomVerify) {
    await verifyReceivedCredential(issuerTrust, received);
  }
  return received;
}
