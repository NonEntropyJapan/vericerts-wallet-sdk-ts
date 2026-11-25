/**
 * SIOPv2 で Pseudonym ログイン。
 *
 * RP の SIOPv2 Authorization Request（`client_id` / `nonce`）を受け、RP 別に派生した Pseudonym
 * 秘密鍵で自己発行 ID Token（`iss=sub=urn:pseudonym:<hash(pub)>`（SIOPv2 の self-issued 判定）,
 * `aud=client_id`, `nonce`）に
 * 署名して返す。同一 RP への再訪問では派生が決定的なため同一 subject を提示する（継続性）。
 * 異なる RP には HKDF の一方向性により相関不能な別 subject を提示する（相関不能性）。
 *
 * 本モジュールは ID Token 生成のみを担い、`direct_post` の HTTP 送信・RP メタデータ検証
 * （Trust Framework）は上位層の責務とする。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に privateKey・
 * JWT 本文を含めない。
 */

import { signCompactJws } from '../../credential/vc/compact-jws.js';
import { buildJwsHeader, createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds, isLifetimeSeconds } from '../../primitives/option-guard.js';
import { isNonBlankString, isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { derivePseudonym } from './derive.js';
import type { PseudonymIdToken, SiopRequest } from './types.js';

/** ID Token の既定有効期間（秒）。5 分。 */
const DEFAULT_ID_TOKEN_LIFETIME_SECONDS = 5 * 60;

/** `presentPseudonym` のオプション。 */
export interface PresentPseudonymOptions {
  /** 発行時刻（NumericDate、秒）。テスト・決定性のため注入する。 */
  readonly nowSeconds: number;
  /** ID Token の有効期間（秒）。既定は 5 分。 */
  readonly lifetimeSeconds?: number;
}

/**
 * SIOPv2 で Pseudonym ログイン用の ID Token を生成する。
 *
 * `masterSeed` と `rpIdentifier` から Pseudonym 鍵を派生し（`derivePseudonym`）、その秘密鍵で
 * 自己発行 ID Token に署名する。`sub` は `urn:pseudonym:<hash(pub)>`、`aud` は要求の `client_id`、
 * `nonce` は要求の `nonce`（リプレイ防止）。`sub_jwk` に派生公開鍵の EC JWK を含め、RP が
 * 署名検証できるようにする。
 *
 * @param request SIOPv2 Authorization Request（`clientId` / `nonce`）。
 * @param rpIdentifier RP のクライアント識別子（正規化前。通常 `request.clientId` と同一値）。
 * @param masterSeed マスター種（`pseudonym_master_seed`）。
 * @param opts 発行オプション（`nowSeconds` / `lifetimeSeconds`）。
 * @returns 署名済み ID Token と subject 識別子。
 * @throws RP 識別子不正・要求フィールド（`clientId` / `nonce`）欠落・必須オプション
 *   （`nowSeconds`）欠落（code `10201`）、鍵派生失敗（code `10202`）の場合。
 */
export function presentPseudonym(
  request: SiopRequest,
  rpIdentifier: string,
  masterSeed: Uint8Array,
  opts: PresentPseudonymOptions,
): PseudonymIdToken {
  // 検証した値をそのまま署名に使う（TOCTOU 回避）。検証後にもう一度読み直すと、アクセサ汚染
  // （呼ばれるたび別の値を返す getter）で「検証した値」と「署名した値」が食い違い得る。
  const { clientId, nonce } = readValidSiopRequest(request);
  const key = derivePseudonym(rpIdentifier, masterSeed);
  try {
    const signer = createPrivateKeySigner(key.privateKey, 'ES256');

    // 任意プロパティは自身のプロパティに限って読む。`lifetimeSeconds` を省略した
    // 正当な提示でも継承値を拾うと `exp` が攻撃者の選んだ値になり、**無期限に近い署名済み
    // ID Token** を発行してしまう。
    const lifetime =
      ownProperty<number>(opts, 'lifetimeSeconds') ?? DEFAULT_ID_TOKEN_LIFETIME_SECONDS;

    // 必須プロパティも同様に自身のプロパティに限って読む。`nowSeconds` は署名対象
    // クレーム（`iat` / `exp`）であり、鎖読みのままだと省略した提示で攻撃者の選んだ時刻の
    // ID Token を署名させられる。欠落・型不正は `as` で下流へ流さず fail-closed に拒否する。
    const nowSeconds = ownProperty<number>(opts, 'nowSeconds');
    // 非有限・負値・文字列は JWT に `null` 等で載り検証不能になる。寿命も正の有限数に限る。
    if (!isEpochSeconds(nowSeconds) || !isLifetimeSeconds(nowSeconds, lifetime)) {
      throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
    }

    const claims = {
      iss: key.subject,
      sub: key.subject,
      aud: clientId,
      nonce,
      iat: nowSeconds,
      exp: nowSeconds + lifetime,
      // SIOPv2: RP が自己発行 ID Token を検証するための subject 鍵。
      sub_jwk: signer.publicKeyJwk,
    };

    const idToken = signCompactJws(buildJwsHeader(signer, 'JWT'), claims, signer);
    return { idToken, subject: key.subject };
  } finally {
    // 派生秘密鍵は署名完了後、例外発生時も含めて速やかにメモリから消去する。
    // `derivePseudonym` はステートレスなため、鍵を使い終えた呼び出し元が消去を担う。
    key.privateKey.fill(0);
  }
}

/**
 * SIOPv2 Request の必須フィールド（`clientId` / `nonce`）を検証し、検証済みの値を返す。
 *
 * `client_id` は ID Token の `aud`（対象 RP）に、`nonce` はリプレイ防止に必須。欠落・空の場合は
 * RP 識別子不正（code `10201`）として拒否する。
 *
 * 各フィールドは自身のプロパティとして**1 回だけ**読み、その値を呼び出し側がそのままクレームに
 * 載せる。検証後にもう一度読み直すと、`Object.prototype` のアクセサ汚染や
 * getter を持つ Request で「検証した値」と「署名した値」が食い違う（TOCTOU）。
 *
 * @param request 検証対象の SIOPv2 Request。
 * @returns 検証済みの `clientId` / `nonce`。
 * @throws 必須フィールド欠落・空の場合（VericertsError、code `10201`）。
 */
function readValidSiopRequest(request: SiopRequest): { clientId: string; nonce: string } {
  if (request === null || typeof request !== 'object') {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  const clientId = ownProperty<string>(request, 'clientId');
  const nonce = ownProperty<string>(request, 'nonce');
  // 非空 / 非空白の判定は SDK 内の単一の共有ヘルパで行う（層ごとに複製しない）。
  // `clientId` は RP 識別子なので空白のみも弾き、`nonce` は値そのものが空でなければよい。
  if (!isNonBlankString(clientId) || !isNonEmptyString(nonce)) {
    throw new VericertsError(ErrorCodes.RP_IDENTIFIER_INVALID);
  }
  return { clientId, nonce };
}
