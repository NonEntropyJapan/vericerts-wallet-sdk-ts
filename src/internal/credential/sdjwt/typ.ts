/**
 * SD-JWT VC の `typ`（JWS ヘッダ media type）に関する SSOT。
 *
 * IETF draft-ietf-oauth-sd-jwt-vc / OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 準拠。
 *
 * draft-ietf-oauth-sd-jwt-vc は media type を `vc+sd-jwt` から `dc+sd-jwt` に改称した。
 * 本 SDK は発行の既定を新 typ（`dc+sd-jwt`）とし、移行期間中は検証・表示で旧 typ
 * （`vc+sd-jwt`）も受理する（発行は明示 opt-in のみ）。
 *
 * SD-JWT VC では、Issuer-signed JWT の JWS ヘッダ `typ` と OID4VCI / OID4VP の
 * credential format 識別子が同一文字列である。したがって本モジュールの定数は
 * format 識別子（`format: 'dc+sd-jwt'` 等）としてもそのまま再利用する。
 *
 * セキュリティ上の注意:
 * - `typ` を検証しないと `kb+jwt` / `JWT` 等を SD-JWT VC として受理する typ 混同
 *   （type confusion）を許すため、検証側は存在する `typ` を必ず受理集合と照合する
 *   （`assertAcceptedSdJwtVcTypIfPresent`）。受理対象外は `3002` で拒否する。
 * - 一方で `typ` の欠落は受理する。`typ` は JWS ヘッダ＝署名対象であり、攻撃者による剥奪・改変は
 *   必ず署名検証失敗を伴う。したがって欠落を拒否しても type confusion 対策としては何も足さず、
 *   `typ` を付けない旧 Issuer 発行の保存済みクレデンシャルを壊す実害だけが残る。
 * - 例外メッセージや `context` に入力値（不正な typ 文字列）を含めない。
 * - 受理集合の権威実体はモジュール内に閉じ（`ACCEPTED_TYPS`）、公開するのは変更不能なビュー
 *   （`ACCEPTED_SD_JWT_VC_TYPS`）だけとする。可変な `Set` をそのまま公開すると利用者側の
 *   `(SET as Set<string>).add('kb+jwt')` でプロセス全体の受理集合が恒久的に広がり、上記の
 *   type confusion ガードが無力化される。ガードは公開ビューを一切読まないため、
 *   `Set.prototype.add.call` によるビューの汚染も受理判定には波及しない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { toFrozenSetView } from '../../prototype-safety/frozen-set.js';

/** SD-JWT VC の `typ`（発行の既定）。draft-ietf-oauth-sd-jwt-vc / HAIP 1.0 準拠。 */
export const SD_JWT_VC_TYP = 'dc+sd-jwt';

/** SD-JWT VC の旧 `typ`（移行前）。受理・表示は対応するが、発行は明示 opt-in のみ。 */
export const SD_JWT_VC_TYP_LEGACY = 'vc+sd-jwt';

/** SD-JWT VC として受理する `typ`（新 typ または移行期間の旧 typ）。 */
export type SdJwtVcTyp = typeof SD_JWT_VC_TYP | typeof SD_JWT_VC_TYP_LEGACY;

/**
 * 受理する `typ` の正準リスト（メンバ列挙の SSOT。SDK 内部専用で公開 API には出さない）。
 *
 * module-private な権威集合（`ACCEPTED_TYPS`）も、`auth/matcher.ts` の `SD_JWT_VC_FORMATS` も
 * このリストから組み立てる。各所がそれぞれ `[SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY]` を書き写すと
 * メンバの追加・削除が片方だけに反映される取りこぼしが起きるためである。公開ビューを別の公開ビュー
 * から派生させる（＝非権威な値を権威扱いする）ことは禁止で、派生元は必ず本リストとする。
 */
export const ACCEPTED_SD_JWT_VC_TYP_VALUES: readonly SdJwtVcTyp[] = [
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
];

/**
 * 検証で受理する `typ` の権威集合（移行期間中は新旧双方を受理する）。
 *
 * 判定はこの module-private な集合だけを読む。公開値（`ACCEPTED_SD_JWT_VC_TYPS`）を読むと、
 * 外部から差し替え・追記された内容がそのまま受理判定になってしまうためである。
 */
const ACCEPTED_TYPS: ReadonlySet<string> = new Set<SdJwtVcTyp>(ACCEPTED_SD_JWT_VC_TYP_VALUES);

/**
 * 検証で受理する `typ` の集合（移行期間中は新旧双方を受理する）。
 *
 * 公開するのは権威集合そのものではなく変更不能なビューである（`toFrozenSetView`）。変更操作は
 * 経路を問わず `TypeError` になるが、`Object.freeze` を掛けたわけではないので
 * `Object.isFrozen()` は `false` を返す（`frozen-set.ts` の注記を参照）。
 * 読み取り操作（`has` / `size` / スプレッド / `new Set(view)` / `forEach` 等）は従来どおり動く。
 */
export const ACCEPTED_SD_JWT_VC_TYPS: ReadonlySet<string> = toFrozenSetView(ACCEPTED_TYPS);

/**
 * 値が SD-JWT VC として受理できる `typ` かを判定する。
 *
 * @param typ 判定対象（JWS ヘッダの `typ`。未知の型・欠落を想定して `unknown`）。
 * @returns 受理対象（`dc+sd-jwt` / `vc+sd-jwt`）なら true。
 */
export function isAcceptedSdJwtVcTyp(typ: unknown): typ is SdJwtVcTyp {
  // 公開ビューではなく権威集合を読む（公開値が汚染されても受理判定は広がらない）。
  return typeof typ === 'string' && ACCEPTED_TYPS.has(typ);
}

/**
 * `typ` が存在する場合に限り、SD-JWT VC として受理できる値かを検証する（検証側の入口ガード）。
 *
 * `kb+jwt` / `JWT` 等を SD-JWT VC として受理する typ 混同を塞ぐため、存在して受理対象外の `typ` は
 * `3002` で拒否する（発行側 `resolveIssuanceTyp` と同一コード＝発行・検証で対称）。「署名不一致」を
 * 意味する `3010` は使わない。typ 混同はほんとうの改ざんではなく、署名検証を行わない
 * `toQueryableFromSdJwt` 経路からも投げられるためである。
 *
 * `typ` の欠落は受理する。`typ` は JWS ヘッダ＝署名対象なので、攻撃者が剥奪・改変すれば必ず署名
 * 検証が失敗する。したがって欠落を拒否しても type confusion 対策としては何も足さず、`typ` を
 * 付けない旧 Issuer が発行した保存済みクレデンシャルを一律に検証失敗させる実害だけが残る。
 *
 * 表明シグネチャ（`asserts`）なので、呼び出し後は `typ` が `SdJwtVcTyp | undefined` に絞り込まれる。
 *
 * @param typ JWS ヘッダの `typ`（欠落可）。
 * @throws `typ` が存在し受理対象外の場合（VericertsError、code `3002`。入力値は含めない）。
 */
export function assertAcceptedSdJwtVcTypIfPresent(
  typ: unknown,
): asserts typ is SdJwtVcTyp | undefined {
  if (typ === undefined) {
    return;
  }
  if (!isAcceptedSdJwtVcTyp(typ)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
}

/**
 * 発行時に使う `typ` を決定する。
 *
 * 未指定なら既定の `dc+sd-jwt` を返す。旧 `vc+sd-jwt` は明示指定した場合のみ採用する。
 *
 * @param typ 発行オプションで指定された `typ`（未指定可）。
 * @returns 発行に用いる `typ`。
 * @throws 受理対象外の `typ` を指定した場合（VericertsError、code `3002`。入力値は含めない）。
 */
export function resolveIssuanceTyp(typ: string | undefined): SdJwtVcTyp {
  if (typ === undefined) {
    return SD_JWT_VC_TYP;
  }
  if (!isAcceptedSdJwtVcTyp(typ)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  return typ;
}
