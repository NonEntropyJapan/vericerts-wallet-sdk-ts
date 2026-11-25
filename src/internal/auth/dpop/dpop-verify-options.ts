/**
 * `verifyDpopProof` の検証条件の型と、その前提条件ガード。
 *
 * RFC 9449 §4.3 step 12 に従い、アクセストークンと併せて提示される proof の鍵を照合する。
 *
 * `verifyDpopProof` が `options` から読み取る値はすべて本モジュールに集約する。
 * 読み取り規則（own プロパティ限定か否か）が 1 か所に揃っていないと、一部の項目だけ
 * `Object.prototype` 汚染に耐える非対称な実装に戻りやすいため。
 *
 * 検証本体（`dpop-verify.ts`）から型定義を分離しているのは、DPoP 検証条件が
 * 「アクセストークン束縛あり / なし」の判別可能ユニオンで表現され、その不変条件の説明に相応の
 * 分量を要するため（linterly の 1 ファイル 300 行上限）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` にアクセストークン・
 * proof JWT・鍵素材・クレーム値を含めない。
 */

import { CLOCK_SKEW_PROFILE, resolveClockSkewSeconds } from '../../credential/time-claims.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import { normalizeHtu } from './dpop-common.js';

/** `verifyDpopProof` の検証条件のうち、アクセストークン束縛に依存しない共通部分。 */
export interface VerifyDpopProofBaseOptions {
  /** 期待する HTTP メソッド（大文字小文字を区別して比較する）。 */
  readonly htm: string;
  /** 期待する HTTP target URI（クエリ・フラグメントを除去して比較する）。 */
  readonly htu: string;
  /** 指定時のみ `nonce` クレームを検証する（RFC 9449 §8）。欠落・不一致とも code `4086`。 */
  readonly nonce?: string;
  /**
   * `iat` に許容する最大経過秒数（過去方向）。省略時 `DEFAULT_DPOP_MAX_AGE_SECONDS`（30）。
   * 上限も 30 で、超過値・非負整数でない値は `4015 CLOCK_SKEW_OPTION_INVALID` で拒否する。
   */
  readonly maxAgeSeconds?: number;
  /**
   * `iat` に許容する未来方向のスキュー秒数。省略時 `DEFAULT_DPOP_CLOCK_SKEW_SECONDS`（30）。
   * 上限も 30 で、超過値・非負整数でない値は `4015 CLOCK_SKEW_OPTION_INVALID` で拒否する。
   */
  readonly clockSkewSeconds?: number;
  /** 現在時刻（エポック秒）。省略時は `Math.floor(Date.now() / 1000)`。 */
  readonly nowSeconds?: number;
}

/**
 * アクセストークンと併せて proof を検証する場合の条件。
 *
 * RFC 9449 §4.3 step 12 は、proof がアクセストークンと共に提示される場合に proof 公開鍵と
 * アクセストークンの `cnf.jkt` が一致することの確認を MUST としている。`expectedJkt` を省略可能に
 * すると、`ath` はアクセストークン値のハッシュにすぎない（トークンを入手した攻撃者なら誰でも
 * 一致させられる）ため、盗んだ DPoP-bound トークンに攻撃者鍵の proof を添えるだけで
 * sender-constraining を完全に回避できてしまう。そこで `accessToken` 指定時は `expectedJkt` を
 * **型レベルで必須**にする。
 */
export interface VerifyDpopProofWithAccessTokenOptions extends VerifyDpopProofBaseOptions {
  /** `ath` 照合の対象アクセストークン（値は保持・記録しない）。 */
  readonly accessToken: string;
  /** アクセストークンの `cnf.jkt`（RFC 7638 サムプリント）。省略不可。 */
  readonly expectedJkt: string;
}

/** アクセストークンを伴わずに proof のみを検証する場合の条件。 */
export interface VerifyDpopProofWithoutAccessTokenOptions extends VerifyDpopProofBaseOptions {
  /** 本 variant はアクセストークン束縛を検証しないため、指定してはならない。 */
  readonly accessToken?: undefined;
  /** 指定時のみ `cnf.jkt`（RFC 7638 サムプリント）との鍵束縛を検証する。 */
  readonly expectedJkt?: string;
}

/**
 * `verifyDpopProof` の検証条件（判別可能ユニオン）。
 *
 * `accessToken` を指定する variant では `expectedJkt` も必須になる（RFC 9449 §4.3 step 12）。
 */
export type VerifyDpopProofOptions =
  | VerifyDpopProofWithAccessTokenOptions
  | VerifyDpopProofWithoutAccessTokenOptions;

/**
 * `accessToken` 指定時に `expectedJkt` が併せて渡されていることを表明する。
 *
 * 型でも同じ不変条件を強制しているが、JS からの呼び出しや `as` によるキャストは型検査を迂回できる。
 * この組み合わせを黙って受理すると sender-constraining が無効化されるため、ランタイムでも拒否する。
 *
 * エラーコードに `4085`（`DPOP_KEY_BINDING_MISMATCH`）を用いるのは、この状態が
 * 「RFC 9449 §4.3 step 12 の鍵一致確認を実施できておらず、鍵束縛を確認済みと言えない」ことを
 * 意味するため。`4080`（形式不正）は proof 自体の不備を示すコードであり、proof に問題が無い本ケース
 * では原因を誤らせる。fail-closed に束縛不一致として扱う。
 *
 * @param options 検証条件（未検証の組み合わせを含み得る）。
 * @throws `accessToken` 指定かつ `expectedJkt` 未指定の場合（VericertsError、code `4085`）。
 */
export function assertAccessTokenKeyBinding(options: VerifyDpopProofOptions): void {
  // 任意プロパティは own 限定で読む。継承した `expectedJkt` は「鍵バインドを
  // 指定済み」に化けて 4085 のガードを素通りさせ、`accessToken` を渡した検証で cnf.jkt 照合が
  // 実質スキップされる。
  if (
    ownProperty<string>(options, 'accessToken') !== undefined &&
    ownProperty<string>(options, 'expectedJkt') === undefined
  ) {
    throw new VericertsError(ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  }
}

/** `verifyDpopProof` が `iat` の鮮度判定に使う実効窓（`resolveDpopFreshnessWindow` の戻り値）。 */
export interface DpopFreshnessWindow {
  /** `iat` に許容する未来方向のスキュー秒数。 */
  readonly clockSkewSeconds: number;
  /** `iat` に許容する最大経過秒数（過去方向）。 */
  readonly maxAgeSeconds: number;
}

/**
 * `clockSkewSeconds` / `maxAgeSeconds` を検証し、`iat` の実効鮮度窓へ解決する。
 *
 * DPoP proof の鮮度窓の既定値と上限は前後 30 秒。未来側は `clockSkewSeconds`、
 * 過去側は `maxAgeSeconds` で個別に短縮できる。
 * どちらか一方でも `CLOCK_SKEW_PROFILE.dpopProof`（30）を超えられると proof のリプレイ窓が
 * 規定より広がるため、両方に同じキャップを適用して `4015 CLOCK_SKEW_OPTION_INVALID` で拒否する。
 * VC / VP 経路と同じ `resolveClockSkewSeconds` を使い、受理条件（非負整数かつキャップ以下）を
 * 経路間で揃える。
 *
 * @param options 検証条件。
 * @returns 実効の鮮度窓（未指定の側は既定値 = キャップ）。
 * @throws いずれかが非負整数でない / 30 を超える場合（VericertsError、code `4015`）。
 */
export function resolveDpopFreshnessWindow(options: VerifyDpopProofOptions): DpopFreshnessWindow {
  // 任意オプションは自身のプロパティに限って読む。継承値を拾うと、これらを
  // 指定していない正当な検証でも実効の鮮度窓が汚染値に置き換わる。
  return {
    clockSkewSeconds: resolveClockSkewSeconds(
      'dpopProof',
      ownProperty<number>(options, 'clockSkewSeconds'),
    ),
    maxAgeSeconds: resolveClockSkewSeconds(
      'dpopProof',
      ownProperty<number>(options, 'maxAgeSeconds'),
    ),
  };
}

/**
 * `htm` / `htu` / `nonce` の HTTP 束縛を照合する（RFC 9449 §4.3 step 8-9、§8）。
 *
 * HTTP メソッドは大文字小文字を区別するトークン（RFC 9110 §9.1）のため、case folding せず完全一致で
 * 比較する。`htu` は双方を `normalizeHtu` で正規化してから比較し、いずれかがパース不能なら不一致と
 * みなす。
 *
 * `nonce` の欠落・不一致だけは `htm` / `htu` 不一致（`4083`）と別コード `4086` で通知する。RFC 9449
 * §8 / §9 は nonce が必要・不正な場合に AS / RS が `use_dpop_nonce` チャレンジ（AS: 400 +
 * `error=use_dpop_nonce`、RS: 401 + `WWW-Authenticate: DPoP error=use_dpop_nonce` と `DPoP-Nonce`
 * ヘッダ）を返すことを要求しており、同一コードに潰すと呼び出し側がこの応答を出し分けられないため。
 * 欠落と不一致はどちらも同じチャレンジで応答するので 1 コードで足りる。
 *
 * 照合値は**自身のプロパティに限って**読む。`htm` / `htu` は型の上では必須だが、JS
 * からの呼び出しや `as` によるキャストは型検査を迂回できる。これらをプロトタイプ鎖で読むと、
 * `Object.prototype` が汚染された環境では**照合値を省略した呼び出しでも汚染値が「期待する HTTP
 * 束縛」として使われる**。攻撃者は自分が選んだ `htm` / `htu` を持つ proof を用意すれば束縛検査を
 * 通せるため、RFC 9449 §4.3 step 8-9 が防いでいる「別エンドポイント向け proof の使い回し」が
 * 成立してしまう。`nonce` も汚染値が期待値に化けると `use_dpop_nonce` の運用が攻撃者の制御下に入る。
 * own プロパティとして存在しない場合は照合しようが無いので fail-closed に `4083` で落とす。
 *
 * 同じ `options` の `nowSeconds` / `clockSkewSeconds` / `maxAgeSeconds`（`resolveDpopFreshnessWindow`）
 * や `accessToken` / `expectedJkt`（`assertAccessTokenKeyBinding` / `resolveDpopAccessTokenBinding`）は
 * 既に own 限定で読んでおり、ここだけ鎖読みで残すと関数ごとに違う規則で同じ options を解釈すること
 * になる。いずれも純データの値なので `ownProperty` を用いる（DI 依存ではないため
 * `nonObjectPrototypeProperty` は使わない）。
 *
 * @param claims proof payload から取り出した `htm` / `htu` / `nonce`。
 * @param options 検証条件。
 * @returns 正規化済みの `htu`。
 * @throws `htm` / `htu` が欠落または期待値と一致しない場合（VericertsError、code `4083`）、
 *         `nonce` が欠落・不一致の場合（同、code `4086`）。
 */
export function assertHttpBinding(
  claims: { readonly htm: string; readonly htu: string; readonly nonce?: string },
  options: VerifyDpopProofOptions,
): string {
  const expectedHtm = ownProperty<string>(options, 'htm');
  if (expectedHtm === undefined || claims.htm !== expectedHtm) {
    throw new VericertsError(ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  }
  const rawExpectedHtu = ownProperty<string>(options, 'htu');
  const actualHtu = normalizeHtu(claims.htu);
  const expectedHtu = rawExpectedHtu === undefined ? undefined : normalizeHtu(rawExpectedHtu);
  if (actualHtu === undefined || expectedHtu === undefined || actualHtu !== expectedHtu) {
    throw new VericertsError(ErrorCodes.DPOP_HTTP_BINDING_MISMATCH);
  }
  const expectedNonce = ownProperty<string>(options, 'nonce');
  if (
    expectedNonce !== undefined &&
    (claims.nonce === undefined || !timingSafeEqualString(claims.nonce, expectedNonce))
  ) {
    throw new VericertsError(ErrorCodes.DPOP_NONCE_REQUIRED);
  }
  return actualHtu;
}

/** `verifyDpopProof` が `ath` / `cnf.jkt` 照合に用いる期待値（`resolveDpopAccessTokenBinding`）。 */
export interface DpopAccessTokenBinding {
  /** `ath` 照合の対象アクセストークン。own プロパティとして無ければ `undefined`。 */
  readonly accessToken: string | undefined;
  /** 期待する `cnf.jkt`。own プロパティとして無ければ `undefined`。 */
  readonly expectedJkt: string | undefined;
}

/**
 * `accessToken` / `expectedJkt` を**自身のプロパティに限って**読み出す。
 *
 * `assertAccessTokenKeyBinding` は既に own 限定でこの 2 つを読んでいるため、照合本体だけが
 * 鎖読みだと**同じ options に対して前提条件ガードと照合が別の値を見る**。実際、`accessToken` を
 * 渡していない正当な検証でも、汚染された `accessToken` はガードを素通りしたうえで `ath` 照合を
 * 有効化し、`ath` を持たない正当な proof を 4084 で落とす。
 *
 * @param options 検証条件。
 * @returns own プロパティとして存在するアクセストークン束縛の期待値。
 */
export function resolveDpopAccessTokenBinding(
  options: VerifyDpopProofOptions,
): DpopAccessTokenBinding {
  return {
    accessToken: ownProperty<string>(options, 'accessToken'),
    expectedJkt: ownProperty<string>(options, 'expectedJkt'),
  };
}

/** DPoP proof の `iat` に許容する最大経過秒数（既定値 30 秒）。 */
export const DEFAULT_DPOP_MAX_AGE_SECONDS = CLOCK_SKEW_PROFILE.dpopProof;

/** DPoP proof の `iat` に許容する未来方向のクロックスキュー秒数（既定値 30 秒）。 */
export const DEFAULT_DPOP_CLOCK_SKEW_SECONDS = CLOCK_SKEW_PROFILE.dpopProof;
