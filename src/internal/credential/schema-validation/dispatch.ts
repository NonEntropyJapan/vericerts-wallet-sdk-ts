/**
 * スキーマ検証経路の自動判定と実行（`validateClaimsAgainstSchema`）。
 *
 * **呼び出し側に経路を選ばせない。** クレデンシャルの形式（`vct` + `claims` か
 * `credentialSubject` か）から経路を判定し、対応する fail-safe 入口へ委譲する。どちらとも
 * 判定できない入力は**検証せず**通過させる（`route: 'none'` + `schemaAvailable: false`）。
 * **両形式のシグナルを併せ持つ入力は両経路で検証して結果を合成する**（`route: 'both'`）。
 * 片方に倒すと、良性の `vct`（スキーマ無し = `valid: true`）を併記するだけで実際の
 * `credentialSchema` 検証を回避できてしまうため、優先順位を付けずに両方を課す。
 *
 * 2 つの経路は別エコシステムであり、`vct` と `credentialSchema` の claim を相互に流用しない。
 * 本モジュールは判定と委譲のみを行い、取得・検証・キャッシュは各経路の実装が担う。
 *
 * セキュリティ上の注意:
 * - 形式判定のプロパティ存在確認は `Object.hasOwn` で行う。`in` 演算子や `!== undefined` は
 *   プロトタイプチェーン（`constructor` 等）経由で成立し得るため、細工されたオブジェクトで
 *   経路判定が誤爆する。
 * - 判定・委譲のいずれでも URL・クレーム値をログや例外へ持ち出さない。
 */

import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { SchemaError, SchemaFailSafeResult } from '../json-schema/index.js';
import { isPlainObject as isRecord } from '../object-guards.js';
import { validateClaimsAgainstTypeMetadata } from '../sdjwt/type-metadata/index.js';
import type { VerifiedSdJwt } from '../sdjwt/verify.js';
import { validateClaimsAgainstCredentialSchema } from '../vc/credential-schema/index.js';
import type { VerifiableCredential } from '../vc/vc.js';
import type {
  RoutedSchemaValidationOptions,
  RoutedSchemaValidationResult,
  SchemaValidatableCredential,
  SchemaValidationRoute,
} from './types.js';

/** 自身のプロパティとして持つ `key` が素の object か判定する。 */
function hasOwnRecord(value: Record<string, unknown>, key: string): boolean {
  return Object.hasOwn(value, key) && isRecord(value[key]);
}

/** SD-JWT VC のシグナル（`vct` = 非空文字列 と `claims` = object）を自身のプロパティに持つか。 */
function hasSdJwtSignals(credential: Record<string, unknown>): boolean {
  return (
    Object.hasOwn(credential, 'vct') &&
    typeof credential.vct === 'string' &&
    credential.vct.length > 0 &&
    hasOwnRecord(credential, 'claims')
  );
}

/**
 * クレデンシャルの形式からスキーマ検証経路を判定する。
 *
 * - `vct`（非空文字列）と `claims`（object）を自身のプロパティとして持つ = SD-JWT VC
 *   （`VerifiedSdJwt` 互換）→ Type Metadata 経路。
 * - `credentialSubject`（object）を自身のプロパティとして持つ = W3C VC → `credentialSchema` 経路。
 * - **両方**のシグナルを自身のプロパティとして持つ → `both`（両経路で検証する）。どちらの
 *   エコシステムの入力なのか決められない以上、先に書いてある分岐へ流す（＝もう片方の検証を
 *   省く）という決め方は取らない。
 * - いずれにも当てはまらない（object でない場合を含む）→ `none`。
 *
 * 判定は**自身のプロパティのみ**を見る（`Object.hasOwn`）。継承した `vct` で SD-JWT VC と
 * 誤判定させ、`credentialSchema` 経路の検証を回避させる細工を防ぐため。
 *
 * @param credential 判定対象。型が保証されない外部入力も受け取れるよう `unknown` を許容する。
 * @returns 判定した経路。
 */
export function detectSchemaValidationRoute(credential: unknown): SchemaValidationRoute {
  if (!isRecord(credential)) {
    return 'none';
  }
  const sdJwt = hasSdJwtSignals(credential);
  const w3c = hasOwnRecord(credential, 'credentialSubject');
  if (sdJwt && w3c) {
    return 'both';
  }
  if (sdJwt) {
    return 'sd-jwt-vc-type-metadata';
  }
  if (w3c) {
    return 'w3c-vc-credential-schema';
  }
  return 'none';
}

/**
 * 両経路の結果を合成する（`route: 'both'`）。
 *
 * - `valid`: **両方が通ったときだけ** true（片方でも落ちれば false）。
 * - `schemaAvailable`: どちらかで検証できたなら true。
 * - `errors`: 両経路の違反を連結する（空なら省略する）。
 * - `warnings`: 両経路の監査キーの和集合（同じ FO でも 2 回並べない）。
 *
 * @param sdJwt Type Metadata 経路の結果。
 * @param w3c `credentialSchema` 経路の結果。
 * @returns 合成した結果。
 */
function combine(sdJwt: SchemaFailSafeResult, w3c: SchemaFailSafeResult): SchemaFailSafeResult {
  const errors: SchemaError[] = [...(sdJwt.errors ?? []), ...(w3c.errors ?? [])];
  const warnings = [...new Set([...sdJwt.warnings, ...w3c.warnings])];
  return {
    valid: sdJwt.valid && w3c.valid,
    schemaAvailable: sdJwt.schemaAvailable || w3c.schemaAvailable,
    ...(errors.length === 0 ? {} : { errors }),
    warnings,
  };
}

/**
 * クレデンシャルの形式に応じた経路でクレーム構造を検証する。
 *
 * SD-JWT VC なら `validateClaimsAgainstTypeMetadata`、W3C VC なら
 * `validateClaimsAgainstCredentialSchema` へ委譲する。いずれも
 * FO-3 / FO-4 に従う fail-open 入口であり、**同意コールバックと監査記録先を
 * 与えたうえでゲートが通過を許した場合に限り**、取得失敗は `warnings: ['schema_fetch_failed']`、
 * 任意属性のみの違反は `warnings: ['schema_optional_invalid']` として返る。許可されなければ
 * 取得失敗は例外として伝播し、任意属性違反は `valid: false` になる。`failSafePolicy` / `fetchImpl` /
 * `nowMs` と同意・監査オプションは選ばれた経路へ透過的に渡す。両形式のシグナルを併せ持つ入力は
 * 両経路で検証し、結果を {@link combine} で合成する。
 *
 * @param credential 検証対象（W3C VC または `vct` + `claims` を持つ SD-JWT VC）。
 * @param options 共通オプションと経路固有オプション（キャッシュ・計時ウィンドウ）の注入。
 * @returns 検証結果に `route` を添えたもの。判定できない入力は `route: 'none'` で検証しない。
 * @throws Type Metadata の構造不正（`3061`）は常に。選ばれた経路の取得 / 解決失敗
 *         （`3015` / `3016` / `3060`）は fail-open ゲートが通過を許さなかった場合。
 */
export async function validateClaimsAgainstSchema(
  credential: SchemaValidatableCredential,
  options: RoutedSchemaValidationOptions = {},
): Promise<RoutedSchemaValidationResult> {
  // 任意プロパティは自身のプロパティに限って読む。ここで継承値を新しい
  // オブジェクトリテラルへ詰め直すと own プロパティに化け、下流（fail-open ゲート・時刻評価）の
  // own 限定読み取りが無効化される。`failSafePolicy` の汚染値は FO-3 の判定を許可側へ倒し、
  // `fetchImpl` の汚染値はスキーマ取得先を攻撃者の関数へ委譲する。
  const shared = {
    fetchImpl: nonObjectPrototypeProperty<RoutedSchemaValidationOptions['fetchImpl']>(
      options,
      'fetchImpl',
    ),
    nowMs: ownProperty<number>(options, 'nowMs'),
    failSafePolicy: ownProperty<RoutedSchemaValidationOptions['failSafePolicy']>(
      options,
      'failSafePolicy',
    ),
    // 同意コールバック・監査記録先も own 限定で読む。継承値を拾うと、これらを渡していない
    // 正当な呼び出しでも「同意あり・監査シンクあり」が成立し、スキーマ未検証のまま通過する。
    // 関数値だが、DI 依存ではなく利用者が明示的に渡す任意
    // コールバックなので `resolveFailOpen` / `decideFetchFailure` と同じく `ownProperty` を使う。
    requestConsent: ownProperty<RoutedSchemaValidationOptions['requestConsent']>(
      options,
      'requestConsent',
    ),
    onPolicyEvent: ownProperty<RoutedSchemaValidationOptions['onPolicyEvent']>(
      options,
      'onPolicyEvent',
    ),
    auditContext: ownProperty<RoutedSchemaValidationOptions['auditContext']>(
      options,
      'auditContext',
    ),
  };
  // 経路別オプションも own 限定で読む。スプレッド自体は own プロパティしか
  // 写さないが、**スプレッド元**（`options.typeMetadataOptions` 等）をプロトタイプ鎖で読むと、
  // 当該オプションを渡していない呼び出しに攻撃者オブジェクトの中身が丸ごと展開される。
  const typeMetadataOptions = ownProperty<Record<string, unknown>>(options, 'typeMetadataOptions');
  const credentialSchemaOptions = ownProperty<Record<string, unknown>>(
    options,
    'credentialSchemaOptions',
  );
  const route = detectSchemaValidationRoute(credential);

  /** Type Metadata 経路へ委譲する。 */
  const viaTypeMetadata = async (): Promise<SchemaFailSafeResult> => {
    const { vct, claims } = credential as Pick<VerifiedSdJwt, 'claims' | 'vct'>;
    return await validateClaimsAgainstTypeMetadata(vct, claims, {
      ...typeMetadataOptions,
      ...shared,
    });
  };

  /** `credentialSchema` 経路へ委譲する。 */
  const viaCredentialSchema = async (): Promise<SchemaFailSafeResult> =>
    await validateClaimsAgainstCredentialSchema(credential as VerifiableCredential, {
      ...credentialSchemaOptions,
      ...shared,
    });

  if (route === 'sd-jwt-vc-type-metadata') {
    return { ...(await viaTypeMetadata()), route };
  }

  if (route === 'w3c-vc-credential-schema') {
    return { ...(await viaCredentialSchema()), route };
  }

  if (route === 'both') {
    // 逐次実行する。片方が throw した場合にもう片方の取得を宙に浮かせないため。
    const sdJwt = await viaTypeMetadata();
    const w3c = await viaCredentialSchema();
    return { ...combine(sdJwt, w3c), route };
  }

  // 形式を判定できない = スキーマ制約を持たない入力。検証していないことを明示して通過させる。
  return { valid: true, schemaAvailable: false, warnings: [], route: 'none' };
}
