/**
 * Request Object の型（`typ`）と有効期間（`exp` / `nbf` / `iat`）の検査。
 *
 * `jar-signature.ts` は署名・Trust Anchor 到達・発行者同一性までを見るが、**その要求が
 * 「いま」有効かどうか**と**そもそも Request Object として署名されたものか**は見ていなかった。
 * 本モジュールがその 2 点を足す。
 *
 * **なぜ `exp` を必須にするか。** 署名だけを検査すると、一度発行された Request Object は
 * 無期限に有効になる。`request_uri` の取得結果・ログに残ったディープリンク・共有端末などから
 * 入手した攻撃者は、いつでもウォレットの提示フローを再駆動できる。`response_uri` の origin は
 * RP に固定されるので VP Token の宛先は奪われないが、**要求そのものの再利用**を止めるものが
 * 無い。`exp` を持たない Request Object を「期限が無い = 常に有効」と読み替えず拒否する
 * （fail-closed。欠落も `jar_request_expired` へ正規化する）。
 *
 * **なぜ `typ` を検査するか。** `typ` を見ないと、RP が同じ Access Certificate 鍵で署名した
 * 任意の JWS が Request Object として構造上受理され得る（型混同）。SDK は隣の KB-JWT 経路
 * （`credential/sdjwt/key-binding-verify.ts`）で同じ規律を既に敷いている。
 *
 * セキュリティ上の注意: 失敗は `8030` の固定識別子
 * （`jar_typ_mismatch` / `jar_request_expired`）へ正規化し、クレーム値・時刻・`cause` は載せない。
 */

import { assertTimeClaims, CLOCK_SKEW_PROFILE } from '../../credential/time-claims.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { jarFailure } from './jar-failure.js';

/** JAR Request Object の `typ`（RFC 9101 §10.8 / HAIP §5.1）。 */
const JAR_TYP = 'oauth-authz-req+jwt';

/**
 * RFC 9101 §10.8 が後方互換のために認める `typ`。媒体（`application/oauth-authz-req+jwt`）を
 * 名乗らない既存 Verifier を弾かないために受理するが、**それ以外は受理しない**（`typ` 欠落を
 * 含む。「型を名乗らない JWS」は他用途の JWS と区別できないため）。
 */
const JAR_TYP_COMPAT = 'JWT';

/**
 * Request Object の型と有効期間を検査する。
 *
 * 署名検証（手順 3）と発行者同一性（手順 4）を**通った後**に呼ぶ。順序を逆にすると、署名を
 * 確かめていない JWS のクレームで有効期間の分岐が起き、攻撃者が `exp` を選べてしまう。
 *
 * 時刻評価は `credential/time-claims.ts` の `assertTimeClaims` を再利用する（フォーマットごとに
 * 許容スキューが食い違うと、緩い経路が時刻検証の bypass になる）。スキューは `vp` プロファイル
 * （30 秒）。`iat` 未来 / `exp` 期限切れ / `nbf` 未到来 / 時刻型不正はいずれも「この要求は今
 * 有効でない」という同じ結末なので、`jar_request_expired` へまとめて正規化する。
 *
 * @param header デコード済み JWS ヘッダ。
 * @param payload デコード済み JWS payload。
 * @param options `JarTrustOptions`（`now` を own 限定で読む）。
 * @throws `typ` 不一致（8030 `jar_typ_mismatch`）/ `exp` 欠落・期限切れ・時刻不正
 *         （8030 `jar_request_expired`）の場合。
 */
export function requireRequestObjectValidity(
  header: object,
  payload: Record<string, unknown>,
  options: object,
): void {
  // ヘッダ・payload は `parseJsonWithoutPrototype` 由来だが、own 限定読みは多層防御で残す。
  // 鎖読みだと `typ` を**持たない** JWS が `Object.prototype.typ` の汚染値を掴み、
  // ここで閉じるはずの型混同が素通りする。`now` も同様で、継承値が検証基準時刻に化けると
  // 期限切れの Request Object が有効期間内と判定される。
  const typ = ownProperty<unknown>(header, 'typ');
  if (typ !== JAR_TYP && typ !== JAR_TYP_COMPAT) {
    throw jarFailure('jar_typ_mismatch');
  }
  if (ownProperty<unknown>(payload, 'exp') === undefined) {
    // 期限の無い Request Object を「常に有効」と読み替えない。
    throw jarFailure('jar_request_expired');
  }
  const now = ownProperty<unknown>(options, 'now');
  const nowSeconds =
    typeof now === 'number' && Number.isFinite(now) ? now : Math.floor(Date.now() / 1000);
  try {
    assertTimeClaims(payload, nowSeconds, CLOCK_SKEW_PROFILE.vp);
  } catch {
    // 3024 / 3025 / 4014 / 3002 はいずれも JAR 経路では 8030 へ正規化する。
    throw jarFailure('jar_request_expired');
  }
}
