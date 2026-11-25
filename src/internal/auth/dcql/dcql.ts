/**
 * DCQL（Digital Credentials Query Language）クエリのパースと評価。
 *
 * OpenID for Verifiable Presentations 1.0（Draft 24+）準拠。
 *
 * 本モジュールは型定義と、保持クレデンシャル集合に対して候補を評価する **純粋関数** を提供する
 * （ネットワーク・署名検証は伴わない）。RP の JSON を構造体にするパースは `dcql-parse.ts`。
 *
 * 評価ロジック:
 * - `format`: クレデンシャルの format（`jwt_vc_json` / `jwt_vc_json-ld` / `dc+sd-jwt` / `vc+sd-jwt`）と
 *   一致すること。SD-JWT VC の format 識別子は JWS ヘッダの `typ` と同一文字列で、既定は `dc+sd-jwt`、
 *   移行期間中は旧 `vc+sd-jwt` も受理する（`sdjwt/typ.ts` が SSOT）。
 * - `meta.vct_values`: SD-JWT VC の `vct` がいずれかに一致すること（指定時）。
 * - `meta.type_values`: W3C VC の `type` が、内側配列のいずれか 1 つを包含すること（指定時）。
 * - `claims[].path`: JSONPath 風のキー配列で辿ったクレームが存在すること。`values` 指定時は
 *   その値のいずれかに一致すること。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../../credential/sdjwt/typ.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { WorkBudget } from '../../primitives/work-budget.js';
import { toFrozenSetView } from '../../prototype-safety/frozen-set.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { createDcqlWorkBudget } from './budget.js';
import { MAX_DCQL_CREDENTIALS, rejectOversized, rejectTooManyDcqlMatches } from './limits.js';
import { evaluateCredentialRequirement, matchedClaimPaths } from './requirement.js';

/**
 * DCQL クエリ（JSON object）のパース・構造検証。実体は `dcql-parse.ts` にあり、既存の import パス
 * （`./dcql.js`）を保つためここから再エクスポートする（公開 API `src/exports/auth.ts` 経由）。
 */
export { parseDcqlQuery } from './dcql-parse.js';

/**
 * SDK が対応する DCQL format の権威集合。SD-JWT VC の識別子は `sdjwt/typ.ts` が SSOT。
 *
 * format 照合はこの module-private な集合だけを読む。公開値（`SUPPORTED_DCQL_FORMATS`）を読むと、
 * 外部から追記された未対応 format がそのまま受理されてしまうためである。
 *
 * `jwt_vc_json-ld` は `jwt_vc_json` と同じ JWS Enveloping Proof で保護される。
 * SDK の `VerifiableCredential` 型は `@context` を無条件に必須とするため、両者は**ネゴシエーション
 * 時のラベル**であって別個のワイヤ表現ではない。したがって未実装フォーマット（`ldp_vc` /
 * `vc+cose` / `bbs+`）とは異なり、本集合に含めて受理する。
 */
const SUPPORTED_FORMATS: ReadonlySet<string> = new Set([
  'jwt_vc_json',
  'jwt_vc_json-ld',
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
]);

/**
 * SDK が対応する DCQL クレデンシャル format。SD-JWT VC の識別子は `sdjwt/typ.ts` が SSOT。
 *
 * 公開するのは権威集合ではなく変更不能なビューである（`toFrozenSetView`。変更操作は経路を問わず
 * `TypeError` だが `Object.isFrozen()` は `false`）。読み取り操作は従来どおり動く。
 */
export const SUPPORTED_DCQL_FORMATS: ReadonlySet<string> = toFrozenSetView(SUPPORTED_FORMATS);

/** DCQL の単一クレーム条件。 */
export interface DcqlClaim {
  /** クレームのキー配列（例: `["credentialSubject", "name"]`）。 */
  readonly path: readonly string[];
  /** 受理する値の集合（指定時、辿った値がいずれかに一致する必要がある）。 */
  readonly values?: readonly unknown[];
}

/** DCQL のメタ条件。 */
export interface DcqlMeta {
  /** SD-JWT VC Type（`vct`）の受理値。 */
  readonly vct_values?: readonly string[];
  /**
   * W3C VC の `type` の受理値（OID4VP 1.0 の `jwt_vc_json` / `jwt_vc_json-ld` で必須のメタ）。
   *
   * 文字列配列の配列で、**内側の配列のいずれか 1 つ**について、その全要素が VC の `type` に
   * 含まれればマッチする（OR of AND）。
   */
  readonly type_values?: readonly (readonly string[])[];
}

/** DCQL の単一クレデンシャル要件。 */
export interface DcqlCredential {
  /** クエリ内でのこの要件の識別子。 */
  readonly id: string;
  /** 要求 format（`jwt_vc_json` / `jwt_vc_json-ld` / `dc+sd-jwt` / `vc+sd-jwt`）。 */
  readonly format: string;
  /** メタ条件（`vct_values` 等）。 */
  readonly meta?: DcqlMeta;
  /** 要求クレーム条件。 */
  readonly claims?: readonly DcqlClaim[];
}

/** DCQL クエリ。 */
export interface DcqlQuery {
  /** 要求クレデンシャル要件の配列。 */
  readonly credentials: readonly DcqlCredential[];
}

/**
 * DCQL 評価対象として正規化されたクレデンシャル。
 *
 * JWT-VC / SD-JWT VC のいずれも、format・vct・クレーム object へ正規化してから評価する
 * （正規化は `matcher.ts` が担う）。`claims` は path で辿れる object 表現。
 */
export interface QueryableCredential {
  /** クレデンシャル識別子（マッチ結果で参照する。VC の `id` / `jti` 等）。 */
  readonly id: string;
  /** クレデンシャル format（`jwt_vc_json` / `jwt_vc_json-ld` / `dc+sd-jwt` / `vc+sd-jwt`）。 */
  readonly format: string;
  /** SD-JWT VC Type（`vct`）。JWT-VC では `undefined`。 */
  readonly vct?: string;
  /** path で辿れるクレーム object。 */
  readonly claims: Readonly<Record<string, unknown>>;
}

/** DCQL クエリ要件 1 件に対する 1 クレデンシャルのマッチ結果。 */
export interface CredentialMatch {
  /** マッチしたクレデンシャルの ID。 */
  readonly credentialId: string;
  /** マッチした DCQL 要件の ID（`DCQLCredential.id`）。 */
  readonly queryId: string;
  /** マッチに寄与した path（`a.b.c` 形式に連結）一覧。 */
  readonly matchedClaims: readonly string[];
}

/**
 * 要件配列を検査し、要件ごとの `format` を 1 回だけ読んで返す（要件数上限 `8030` と未対応 format の `8050`）。
 *
 * `format` は **1 回だけ** 読み、ゲートと突き合わせの両方でその値を使う
 * （own のアクセサは読むたびに別の値を返せるため。{@link evaluateCredentialRequirement}）。
 */
function gateRequirements(
  query: DcqlQuery,
): { readonly requirement: DcqlCredential; readonly format: string }[] {
  // 要件配列も own 限定（鎖読みだと汚染値が「要件の無いクエリ」に差し替わって評価される）。
  const requirements = ownProperty<readonly DcqlCredential[]>(query, 'credentials') ?? [];
  rejectOversized(requirements, MAX_DCQL_CREDENTIALS);
  const gated: { readonly requirement: DcqlCredential; readonly format: string }[] = [];
  for (const requirement of requirements) {
    const format = ownProperty<string>(requirement, 'format');
    // 公開ビューではなく権威集合を読む（公開値が汚染されても対応 format は広がらない）。
    if (format === undefined || !SUPPORTED_FORMATS.has(format)) {
      // `format` が own に無いときは `context` にキーごと載せない（`format: undefined` は
      // 「8050 が拒否した値」を指さないため）。
      throw new VericertsError(ErrorCodes.FORMAT_NEGOTIATION_FAILED, {
        context: format === undefined ? {} : { format },
      });
    }
    gated.push({ requirement, format });
  }
  return gated;
}

/**
 * DCQL クエリを保持クレデンシャル集合に対して評価し、マッチ候補を返す。
 *
 * 各 DCQL 要件（`DcqlCredential`）について、format / vct / claims をすべて満たすクレデンシャルを
 * 候補として列挙する。1 要件に複数候補がある場合は全件返す（最終選択は UI / 呼び出し側）。
 *
 * 可否は module-private な権威集合 `SUPPORTED_FORMATS`（公開ビュー `SUPPORTED_DCQL_FORMATS` では
 * ない）が決め、非対応なら `FORMAT_NEGOTIATION_FAILED`（8050）を投げる。
 *
 * @param query パース済み DCQL クエリ。
 * @param credentials 正規化済み保持クレデンシャル。
 * @returns マッチ結果の配列（要件 × クレデンシャルの直積のうちマッチしたもの）。
 * @throws 要求 format が未対応の場合（VericertsError、code `8050`）。
 * @throws 要件数が `MAX_DCQL_CREDENTIALS` を超える場合（VericertsError、code `8030`、`context.reason: 'dcql_too_large'`）。
 * @throws 一致件数が `MAX_DCQL_MATCHES` を超える場合（VericertsError、code `8030`、`context.reason: 'too_many_matches'`）。
 * @throws 仕事量予算（要件 × VC の組・`path` のキー・`values` の要素。`MAX_DCQL_WORK_UNITS`）を超える場合
 *   （VericertsError、code `8030`、`context.reason: 'dcql_work_budget_exceeded'`）。
 *
 * `matchedClaims` は要件ごとに 1 つの変更不能な配列を共有する。
 *
 * @param budget 仕事量予算。複数回の評価で共有するときだけ渡す（省略時は呼び出しごとに新しい予算）。
 */
export function evaluateDcql(
  query: DcqlQuery,
  credentials: readonly QueryableCredential[],
  budget: WorkBudget = createDcqlWorkBudget(),
): CredentialMatch[] {
  const gated = gateRequirements(query);

  const matches: CredentialMatch[] = [];
  for (const { requirement, format } of gated) {
    let matchedClaims: readonly string[] | undefined;
    for (const credential of credentials) {
      const hit = evaluateCredentialRequirement(requirement, credential, format, budget);
      if (hit !== undefined) {
        rejectTooManyDcqlMatches(matches.length);
        matchedClaims ??= matchedClaimPaths(requirement);
        matches.push({ ...hit, matchedClaims });
      }
    }
  }
  return matches;
}

/**
 * DCQL クエリを満たす保持クレデンシャルの index 一覧（昇順）を返す。`CredentialMatch` は確保しない。
 *
 * 呼び出し側が使うのが「どのクレデンシャルがいずれかの要件を満たすか」だけのとき用。
 * `evaluateDcql` は要件 R × 保有 H 件ぶんの一致を確保するが、本関数は 1 クレデンシャルにつき最初に満たす
 * 要件で打ち切り、確保量が保有数 H に依らない。要件数上限・format の `8050` は {@link evaluateDcql} と同じ。
 */
export function findMatchingCredentialIndexes(
  query: DcqlQuery,
  credentials: readonly QueryableCredential[],
  budget: WorkBudget = createDcqlWorkBudget(),
): number[] {
  const gated = gateRequirements(query);
  const indexes: number[] = [];
  credentials.forEach((credential, index) => {
    if (
      gated.some(
        ({ requirement, format }) =>
          evaluateCredentialRequirement(requirement, credential, format, budget) !== undefined,
      )
    ) {
      indexes.push(index);
    }
  });
  return indexes;
}
