/**
 * EUDI 受領経路（`receivePID` / `receiveEAA`）の Issuer 署名検証。
 *
 * `EudiFacade`（`facade.ts`）が受領した SD-JWT VC を**セッションへ保持する前**に呼ぶ。保持後に
 * 検証すると、検証に失敗した偽の PID / (Q)EAA が `presentPID` / `presentEAA` の提示候補として
 * 残ってしまう。
 *
 * 規則の実体は `wallet/issuer-trust/` にあり、`wallet.receiveCredential` と共有する。
 * 受領経路によって検証規則が変わらないよう、ここではその判定を委譲する。
 */

import {
  type ReceivedIssuerTrust,
  readVerifyReceived,
  receivedSignatureInvalid,
  runVerifyReceivedHook,
  verifyReceivedSdJwt,
} from '../issuer-trust/index.js';

/**
 * 受領した SD-JWT VC の Issuer 署名を検証する。
 *
 * `opts.verifyReceived` を指定した場合は既定検証を**置換**する（併用しない）。`x5c` / ETSI TSL
 * Trust Anchor など DID 以外の鍵解決を持ち込む正当な呼び出しを、DID 解決の失敗で拒否しないため
 * である。指定の有無と実行する値はどちらも `readVerifyReceived` の**同じ 1 回の読み**から得る
 * （判定と実行で読みを分けると、プロトタイプメソッド / getter 経由の DI で「既定検証もカスタム
 * 検証も走らない」fail-open が生じる。同関数の JSDoc 参照）。
 *
 * `raw` を持たない受領結果は**検証できない**ため fail-closed に落とす（`PIDCredential.raw` /
 * `EAACredential.raw` は型上は省略可能で、現在の受領経路は必ず埋めるが、埋まらない実装が将来
 * 入っても無検証で受理させない）。
 *
 * @param trust Issuer 鍵解決の信頼材料（DID Resolver・`x5c` 用 Issuer 側 Trust Anchor・JWT VC
 *        Issuer Metadata 経路の opt-in と取得シーム。
 *        実体は `wallet/issuer-trust/resolve.ts` の `ReceivedIssuerTrust`）。
 * @param opts 受領オプション（`verifyReceived` を読む。省略時は既定検証）。
 * @param raw 受領した SD-JWT VC のコンパクト表現。
 * @throws Issuer 鍵を解決できない場合（VericertsError、code `3010`、
 *         `reason: 'issuer_key_unresolved'`）、署名が合わない場合・`VericertsError` 以外の値を投げる明示
 *         フックの場合（`3010`、`reason: 'received_credential_signature_invalid'`）。署名不一致以外の
 *         `VericertsError`（`3002` / `3024` 等）は元のコードのまま。
 */
export async function verifyReceivedAttestation(
  trust: ReceivedIssuerTrust,
  opts: object | undefined,
  raw: string | undefined,
): Promise<void> {
  const { hasCustomVerify, verifyReceived } = readVerifyReceived(opts);
  if (raw === undefined) {
    // 理由文字列は `issuer-trust` 側の 1 箇所（`receivedSignatureInvalid`）に閉じる。
    throw receivedSignatureInvalid();
  }
  if (hasCustomVerify) {
    await runVerifyReceivedHook(verifyReceived, raw);
    return;
  }
  await verifyReceivedSdJwt(trust, raw);
}
