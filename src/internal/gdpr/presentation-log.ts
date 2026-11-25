/**
 * 提示イベントの Dashboard ログ記録。
 *
 * Dashboard ログの永続化・署名・Merkle chain は `DashboardLog` が担う。本モジュールは `presentation`
 * エントリ用の payload を組み立てて `DashboardLog.append` へ委譲する薄いアダプタに徹する
 * （`consent-log.ts` の `recordTransactionDataConsent` と同じ構成）。
 *
 * 記録先 `log` と署名鍵 `signer` は提示イベントと同じ `event` オブジェクトで受け取る。
 *
 * セキュリティ / プライバシー上の注意:
 * - **開示したクレームの「値」を payload に含めない。** 記録するのはクレーム**名**までとする。
 *   Dashboard の目的は「いつ・どの RP に・どの属性を出したか」をユーザーに示すことであり、値そのものを
 *   ログへ二重に持たせると、ログ流出時の被害が提示そのものより大きくなる。
 * - `event.log` / `event.signer` は payload に載せない（署名鍵・storage ハンドルはログの内容ではない）。
 */

import type { CredentialSigner } from '../credential/vc/signer.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { DashboardLog } from './dashboard-log/dashboard-log.js';
import type { DashboardLogEntry } from './types.js';

/**
 * Dashboard ログの `presentation` エントリ種別。
 * `vericerts-wallet-sdk/gdpr` から公開する契約。値を変えると利用側の保存データ／出力と食い違う。
 */
export const PRESENTATION_LOG_TYPE = 'presentation' as const;

/** `logPresentationEvent` の入力。 */
export interface PresentationEventInput {
  /** 記録先の Dashboard ログ。 */
  readonly log: DashboardLog;
  /** Dashboard ログエントリの JWS 署名鍵。 */
  readonly signer: CredentialSigner;
  /** 提示先 Verifier 識別子（`client_id` / audience）。 */
  readonly clientId: string;
  /** Authorization Request の `nonce`（省略可）。 */
  readonly nonce?: string;
  /** 提示に用いた VC の ID（値ではなく識別子。省略可）。 */
  readonly credentialIds?: readonly string[];
  /** 開示したクレームの**名前**（値は含めない。省略可）。 */
  readonly disclosedClaims?: readonly string[];
  /** 提示の目的（RP が宣言した `purpose`。省略可）。 */
  readonly purpose?: string;
}

/** `presentation` エントリの payload（`event` から値を除いて組み立てたもの）。 */
export interface PresentationEventPayload {
  /** 提示先 Verifier 識別子。 */
  readonly clientId: string;
  /** Authorization Request の `nonce`（指定時のみ）。 */
  readonly nonce?: string;
  /** 提示に用いた VC の ID（指定時のみ）。 */
  readonly credentialIds?: readonly string[];
  /** 開示したクレームの名前（指定時のみ。値は含まない）。 */
  readonly disclosedClaims?: readonly string[];
  /** 提示の目的（指定時のみ）。 */
  readonly purpose?: string;
}

/**
 * 提示イベントの payload を組み立てる（記録先・署名鍵と、クレームの値は含めない）。
 *
 * 省略された任意メンバはプロパティ自体を生やさない（`undefined` を値として持たせない）。正準 payload が
 * 署名対象になるため、「未指定」と「`undefined` を明示」で signing-input が変わらないようにする。
 *
 * @param event 提示イベント入力。
 * @returns 署名対象の `PresentationEventPayload`。
 */
export function buildPresentationEventPayload(
  event: PresentationEventInput,
): PresentationEventPayload {
  // 任意メンバは own 限定で読む。署名対象の正準 payload へ `Object.prototype.nonce` / `purpose` の汚染値が混入して
  // 監査ログの内容が書き換わらないようにする。
  const nonce = ownProperty<string>(event, 'nonce');
  const credentialIds = ownProperty<readonly string[]>(event, 'credentialIds');
  const disclosedClaims = ownProperty<readonly string[]>(event, 'disclosedClaims');
  const purpose = ownProperty<string>(event, 'purpose');
  return {
    clientId: event.clientId,
    ...(nonce !== undefined ? { nonce } : {}),
    ...(credentialIds !== undefined ? { credentialIds: [...credentialIds] } : {}),
    ...(disclosedClaims !== undefined ? { disclosedClaims: [...disclosedClaims] } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
  };
}

/**
 * 提示イベントを Dashboard ログに署名済みレコードとして記録する。
 *
 * `DashboardLog.append` に `presentation` エントリを委譲する。payload には提示先・nonce・VC の ID・
 * 開示クレーム**名**・目的のみを記録し、クレームの値は含めない（データ最小化）。
 *
 * `async` にしているのは、`Promise` を返す API の失敗を**すべて reject に寄せる**ため。payload 組み立て
 * （`event` が `null` / 非オブジェクトの場合など）で同期例外を投げると、呼び出し側は `try` と `.catch()`
 * の両方を書かないと取りこぼす。`async` なら同期段の例外も reject になり、失敗経路が 1 本になる。
 *
 * @param event 記録先・署名鍵を含む提示イベント。
 * @returns 追記された署名済みエントリ。
 * @throws 署名演算が失敗した場合（VericertsError、code `1020`）。
 */
export async function logPresentationEvent(
  event: PresentationEventInput,
): Promise<DashboardLogEntry> {
  const payload = buildPresentationEventPayload(event);
  // interface はインデックスシグネチャを持たず `Record<string, unknown>` に直接代入できないため、
  // シリアライズ可能な payload を append の型へ橋渡しする（`{ ...payload }` で型を平坦化）。
  return event.log.append(PRESENTATION_LOG_TYPE, { ...payload }, event.signer);
}
