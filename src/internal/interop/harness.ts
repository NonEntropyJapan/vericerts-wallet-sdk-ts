/**
 * HAIP SD-JWT VC 相互運用ペアハーネス。
 *
 * VeriCerts SDK の SD-JWT VC プリミティブ（`credential/sdjwt`）を用いて、HAIP プロファイルの
 * 発行 → 選択的開示提示 → 検証の 1 サイクルを実行する純粋関数ハーネス。実鍵・実署名で完結し、
 * 外部サービス・ネットワークに依存しない（PR / 内部ループ対象）。
 *
 * フロー:
 * 1. Offer:    Issuer が HAIP SD-JWT VC を発行する（`createSdJwt`）。
 * 2. Receive:  Holder が受領した SD-JWT VC を Issuer 鍵で検証する（`verifySdJwt`）。
 * 3. Present:  Holder が要求クレームのみを選択的開示し（`selectDisclosures`）、KB-JWT を付与
 *              （`addKeyBinding`）、Verifier が nonce / aud / cnf 込みで検証する（`verifySdJwt`）。
 */

import type { CreateSdJwtOptions } from '../credential/sdjwt/sdjwt.js';
import { createSdJwt, selectDisclosures } from '../credential/sdjwt/sdjwt.js';
import type { VerifiedSdJwt } from '../credential/sdjwt/verify.js';
import { addKeyBinding, verifySdJwt } from '../credential/sdjwt/verify.js';
import type { CredentialSigner } from '../credential/vc/signer.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';

/** ペアフローの入力（各ロールの鍵と提示要求）。 */
export interface InteropPairInput {
  /** Issuer 署名器（発行）。 */
  readonly issuer: CredentialSigner;
  /** Issuer 検証鍵（Holder / Verifier が発行体署名を検証する鍵）。 */
  readonly issuerKey: PublicKeyJwk;
  /** Holder 署名器（KB-JWT 署名。cnf に対応する鍵）。 */
  readonly holder: CredentialSigner;
  /** SD-JWT VC 発行入力（fixtures）。 */
  readonly credential: CreateSdJwtOptions;
  /** Verifier が提示を要求するクレーム名（選択的開示の対象）。 */
  readonly requestedClaims: readonly string[];
  /** Verifier 発行の nonce（リプレイ対策）。 */
  readonly nonce: string;
  /** Verifier 識別子（audience / client_id）。 */
  readonly audience: string;
  /** KB-JWT の iat（決定性のため注入）。 */
  readonly iatSeconds: number;
  /**
   * 検証時の現在時刻（エポック秒）。既定は `iatSeconds`。
   * 時刻クレーム評価は wall-clock に依存させず、フィクスチャの時刻軸で決定的に行う。
   */
  readonly nowSeconds?: number;
}

/** ペアフローの結果。各段階の成否と復元クレームを返す。 */
export interface InteropPairResult {
  /** Offer: 発行された SD-JWT VC（全 Disclosure 同梱）。 */
  readonly issued: string;
  /** Receive: Holder が受領時に検証した結果。 */
  readonly received: VerifiedSdJwt;
  /** Present: Verifier に提示した SD-JWT VC（選択開示 + KB-JWT）。 */
  readonly presented: string;
  /** Present: Verifier が検証した結果（KB 検証込み）。 */
  readonly verified: VerifiedSdJwt;
}

/**
 * HAIP SD-JWT VC のペア相互運用フロー（Offer → Receive → Present）を 1 サイクル実行する。
 *
 * VeriCerts をどのロールに割り当てても同一のワイヤ形式（SD-JWT VC compact serialization）で
 * 相互運用するため、本ハーネスはロールに依存しない。他 Peer との組合せは、そのロールに対応する
 * 鍵・署名器を差し替えて呼び出す（テストベクターは fixtures を共有する）。
 *
 * @param input 各ロールの鍵・提示要求・nonce / aud。
 * @returns 各段階の SD-JWT VC 文字列と検証結果。
 * @throws いずれかの段階の検証が失敗した場合（`verifySdJwt` の VericertsError をそのまま伝播）。
 */
export function runInteropPair(input: InteropPairInput): InteropPairResult {
  // 任意プロパティは自身のプロパティに限って読む。継承値を新しいオブジェクト
  // リテラルへ詰め直すと own プロパティに化け、下流（`createSdJwt` / `verifySdJwt` /
  // `addKeyBinding`）の own 限定読み取りが無効化される。本ハーネスは `exports/interop.ts` から
  // 公開されており、署名対象の `nonce` / `aud` / `iat` と検証の基準時刻に汚染値が入り得る。
  const iatSeconds = ownProperty<number>(input, 'iatSeconds');
  const nonce = ownProperty<string>(input, 'nonce') as string;
  const audience = ownProperty<string>(input, 'audience') as string;
  // 検証鍵も同関数内で読み方を揃える（nonce / audience / iatSeconds は own 化済み）。
  // クラスインスタンスであり得るため `Object.prototype` 由来だけを弾く。
  const issuerKey = nonObjectPrototypeProperty<PublicKeyJwk>(input, 'issuerKey') as PublicKeyJwk;
  const nowSeconds = ownProperty<number>(input, 'nowSeconds') ?? iatSeconds;
  // 必須フィールドも同じ規律で読む。型上は必須だが、型の無い JS から渡し忘れると
  // 継承値がそのまま発行入力・提示要求・署名器になる。とくに `credential` は
  // `{ ...credential }` で own プロパティへ化けるため、攻撃者が選んだ `vct` / `claims` が
  // **正規の Issuer 鍵で署名されて発行**される（`expectedVct` も同じ汚染値を読むため受領検証も
  // 通る）。純データは own 限定で読む。
  const credential = ownProperty<CreateSdJwtOptions>(input, 'credential') as CreateSdJwtOptions;
  const requestedClaims = ownProperty<readonly string[]>(
    input,
    'requestedClaims',
  ) as readonly string[];
  // 署名器は `class Signer { sign() {} }` のようにプロトタイプメソッドで実装され得るため、
  // own 限定では正当なクラスインスタンスを「未指定」と誤判定する。`Object.prototype` 由来だけを弾く。
  const issuer = nonObjectPrototypeProperty<CredentialSigner>(input, 'issuer') as CredentialSigner;
  const holder = nonObjectPrototypeProperty<CredentialSigner>(input, 'holder') as CredentialSigner;

  // 1. Offer: Issuer が HAIP SD-JWT VC を発行する。
  // 発行時刻を検証側の基準時刻に合わせる（`iat` が `nowSeconds` より未来だと 4014 になるため）。
  const issued = createSdJwt(issuer, {
    ...credential,
    ...(nowSeconds !== undefined ? { nowSeconds } : {}),
  });

  // 2. Receive: Holder が受領時に Issuer 署名・vct を検証する（全 Disclosure 同梱）。
  const received = verifySdJwt(issued, {
    issuerKey,
    expectedVct: credential.vct,
    nowSeconds,
  });

  // 3. Present: 要求クレームのみ選択開示し、KB-JWT を付与して提示する。
  const disclosed = selectDisclosures(issued, requestedClaims);
  const presented = addKeyBinding(disclosed, holder, {
    nonce,
    audience,
    ...(iatSeconds !== undefined ? { iatSeconds } : {}),
  });

  // Verifier が nonce / aud / cnf 込みで検証する（KB 必須）。
  const verified = verifySdJwt(presented, {
    issuerKey,
    expectedVct: credential.vct,
    audience,
    nonce,
    requireKeyBinding: true,
    nowSeconds,
  });

  return { issued, received, presented, verified };
}
