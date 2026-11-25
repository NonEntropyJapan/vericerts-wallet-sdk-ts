/**
 * Issuer 署名検証つきの PID / (Q)EAA 受領（`receivePID` / `receiveEAA`）。
 *
 * `receivePIDCredential` / `receiveEAACredential`（`internal/auth/eudi/issuance`）は OID4VCI の通信と
 * SD-JWT の分解・スキーマ検査しか行わず、**Issuer 署名を検証しない**（`issuerAllowList` が照合する
 * `iss` も未検証 payload の自己申告）。署名検証つきの受領はこの 2 関数だけが担い、`EudiFacade`
 * （`facade.ts`）と、`Wallet` ファサードを使わず自前の保持ストアを持つ拡張機能が共有する。
 * 低レベル関数を直接呼ぶと偽造 PID / (Q)EAA が検証なしで保持されるため、**受領の入口はここだけ**にする。
 *
 * 検証は受領した VC を**呼び出し側が保持する前**に行う（保持後だと偽の PID が提示候補として残る）。
 * 失敗は例外で（署名不一致・鍵解決不能は `3010`、それ以外の `VericertsError` は元のコード）、戻り値は検証済みの VC だけである（fail-closed）。
 */

import type { ReceiveDeps } from '../../internal/auth/eudi/issuance/index.js';
import {
  receiveEAACredential,
  receivePIDCredential,
} from '../../internal/auth/eudi/issuance/index.js';
import type {
  AttestationCatalogueSource,
  EAACredential,
  PIDCredential,
} from '../../internal/eudi/pid/index.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { ReceivedIssuerTrust } from '../issuer-trust/index.js';
import { verifyReceivedAttestation } from './receive-verify.js';

/**
 * PID を受領し、Issuer 署名を検証してから返す。
 *
 * @param offerURI Credential Offer URI。
 * @param deps 受領フローの依存（`ReceiveDeps`）。
 * @param trust Issuer 鍵解決の信頼材料。
 * @param opts `verifyReceived`（明示の検証フック。指定時は既定検証を置換）を読む受領オプション。
 * @throws 署名が合わない・Issuer 鍵を解決できない場合（VericertsError、code `3010`）。署名不一致以外の
 *         `VericertsError`（`3002` / `3024` 等）は元のコード。
 */
export async function receiveVerifiedPID(
  offerURI: string,
  deps: ReceiveDeps,
  trust: ReceivedIssuerTrust,
  opts?: object,
): Promise<PIDCredential> {
  const pid = await receivePIDCredential(offerURI, deps);
  await verifyReceivedAttestation(trust, opts, ownProperty<string>(pid, 'raw'));
  return pid;
}

/**
 * (Q)EAA を受領し、Issuer 署名を検証してから返す。
 *
 * @param offerURI Credential Offer URI。
 * @param catalogue (Q)EAA Catalogue の参照源（未登録 vct は `10003`）。
 * @param deps 受領フローの依存（`ReceiveDeps`）。
 * @param trust Issuer 鍵解決の信頼材料。
 * @param opts `verifyReceived` を読む受領オプション。
 * @throws 署名が合わない・Issuer 鍵を解決できない場合（VericertsError、code `3010`）。署名不一致以外の
 *         `VericertsError`（`3002` / `3024` 等）は元のコード。
 */
export async function receiveVerifiedEAA(
  offerURI: string,
  catalogue: AttestationCatalogueSource,
  deps: ReceiveDeps,
  trust: ReceivedIssuerTrust,
  opts?: object,
): Promise<EAACredential> {
  const eaa = await receiveEAACredential(offerURI, catalogue, deps);
  await verifyReceivedAttestation(trust, opts, ownProperty<string>(eaa, 'raw'));
  return eaa;
}
