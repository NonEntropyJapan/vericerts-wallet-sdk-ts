/**
 * スキーマ検証 2 経路が共有する fail-safe 判定（FO-3 / FO-4）。
 *
 * FO-3 はスキーマ取得失敗、FO-4 は任意属性の違反に対応する。Fail-open の時間上限は既定 60 秒。
 *
 * 判定そのものは `internal/failsafe-policy/` の正準ゲート（`resolveFailOpen`）に委ね、本モジュールは
 * 「スキーマ検証の結果オブジェクトへ落とす」変換だけを持つ。監査キーの文字列をここで再定義しない
 * （二重定義による乖離を避ける）。FO-1 / FO-2（Status List）が `issuer/status-list-fail-open.ts`
 * 経由で同じゲートを通るのと同じ形である。
 *
 * **Fail-open は無条件ではない。** 同意コールバック（`requestConsent`）と監査記録先
 * （`onPolicyEvent`）の双方が与えられ、同意が得られ、監査レコードが記録できた場合にだけ成立する。
 * いずれかを欠く場合・同意が得られない場合・記録に失敗した場合は Fail-closed に倒す。FO-3 は
 * 「元の取得失敗をそのまま伝播する」形（`undefined` を返し呼び出し側が throw）、FO-4 は
 * 「`valid: false` を返す」形で倒れる。
 *
 * W3C VC の `credentialSchema` 経路と SD-JWT VC の Type Metadata 経路は
 * 別エコシステムだが、FO-3 / FO-4 の落とし方は同一である。両経路が参照できる唯一の共有ディレクトリが
 * 本ディレクトリ（`schema-validation/`）のため、ここに置く。dispatch.ts には依存しないので、
 * 経路実装 → 本モジュールの依存は一方向のままである。
 *
 * **時間上限を数えるウィンドウはプロセス共有の既定値を持たない**。
 * `failOpenWindow` を渡さない呼び出しは Fail-closed になる。インスタンスへ閉じ込めたウィンドウが
 * 要る場合は `createSchemaValidator`（`factory.ts`）を使う。呼び出し側は資源識別子（スキーマ URL /
 * `vct` / `schema_uri`）へ経路プレフィックス（`w3c:` / `sdjwt-vct:` / `sdjwt-schema:`）を付け、
 * FO-4 の判定にはさらに {@link credentialFingerprint} を連結してキーを作る。前者は W3C の
 * スキーマ URL と SD-JWT の `vct`（同じく HTTPS URL）がキー名前空間で衝突しないため、後者は
 * 同じ資源を参照する無関係な別クレデンシャルの成功が違反中のクレデンシャルの予算をリセットしない
 * ため。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import type {
  FailOpenId,
  FailOpenWindow,
  FailSafeAuditContext,
  FailSafeAuditRecord,
  FailSafeDecision,
  FailSafePolicy,
  FailSafeWarning,
} from '../../failsafe-policy/index.js';
import { decideFailSafe, resolveFailOpen } from '../../failsafe-policy/index.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { SchemaFailSafeResult, SchemaValidationResult } from '../json-schema/index.js';

/** FO-3 / FO-4 の fail-open ゲートへ渡すオプション（両経路のオプション型が満たす部分集合）。 */
export interface SchemaFailSafeGateOptions {
  /** 既定の fail-safe ポリシーに対する override。 */
  readonly failSafePolicy?: FailSafePolicy;
  /**
   * UI 警告を出しユーザー同意を取るコールバック。
   *
   * 未指定なら同意を取る手段が無いため Fail-open は成立しない。
   */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /**
   * Fail-open 判定の監査ログ記録先。同意・不同意のいずれでも呼ばれる。
   *
   * 監査記録先を省略すると Fail-closed になる。
   */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報。 */
  readonly auditContext?: FailSafeAuditContext;
  /**
   * 時間上限を数えるウィンドウ。
   *
   * **プロセス共有の既定値は持たない**。以前はモジュール単位の共有
   * `Map` を既定に使っていたが、無関係な検証フロー間で 60 秒計時が混線するうえ、計時キー数が
   * `DEFAULT_FAIL_OPEN_MAX_KEYS`（256）に達すると当該プロセスの以降の呼び出しが恒久的に
   * Fail-open できなくなる（Issuer が到達不能なスキーマ URL を 256 種踏ませるだけの DoS）。
   *
   * ウィンドウをインスタンスへ閉じ込めたい場合は `createSchemaValidator`（`factory.ts`）を使う
   * （`internal/issuer/status-list-resolver.ts` の `createStatusListResolver` と同じ、
   * インスタンスごとに `createFailOpenWindow()` を持つパターン）。未指定の場合、本モジュールは
   * 時間上限を計測できないため Fail-closed になる。
   */
  readonly failOpenWindow?: FailOpenWindow;
}

/**
 * 時間上限を数えるウィンドウを決める（注入が有効な形状のときだけそれを使う）。
 *
 * `failOpenWindow` はクラスインスタンスであり得るため `Object.prototype` 由来だけを弾いて読む。
 * 継承値を拾うと、上限を数えるウィンドウが攻撃者のオブジェクトに差し替わり、スキーマ未検証の
 * まま無期限に通過し続ける（共通の失敗様式）。
 *
 * 未指定、あるいは `allow` / `clear` を関数として持たない不正な形状の場合は `undefined` を返す。
 * `gate` 側はこれを「時間上限を計測できない」= Fail-closed として扱う。成功パス
 * （`applySchemaViolations` の `clear` 呼び出し）側もこれを使うことで、不正な形状の注入が
 * `TypeError` として正当なクレデンシャルの検証結果まで巻き込んで落とすことを防ぐ
 * （`failsafe-policy/gate.ts` の `resolveFailOpen` が `window` に施す
 * 形状検証と同じ規律を、ここでも `clear` 呼び出し前に適用する）。
 *
 * `injected`（`options.failOpenWindow`）自体は `nonObjectPrototypeProperty` で読むが、そこで
 * 得た `injected` の `allow` / `clear` を素のドットアクセスで検証すると、own の allow/clear を
 * 持たない不正な形状（`failOpenWindow: {}`）を渡す呼び出しに対して `Object.prototype.allow` /
 * `.clear` の汚染を拾ってしまう（`etsi-tsl/fail-open.ts` の FO-5 で見つかったのと同一のバグ
 * クラス）。`window.allow` / `window.clear` の参照にも `nonObjectPrototypeProperty`
 * を使う。
 */
function resolveWindow(options: SchemaFailSafeGateOptions): FailOpenWindow | undefined {
  const injected = nonObjectPrototypeProperty<FailOpenWindow>(options, 'failOpenWindow');
  if (
    injected === null ||
    typeof injected !== 'object' ||
    typeof nonObjectPrototypeProperty(injected, 'allow') !== 'function' ||
    typeof nonObjectPrototypeProperty(injected, 'clear') !== 'function'
  ) {
    return undefined;
  }
  return injected;
}

/**
 * 指定したキーの Fail-open ウィンドウを破棄する。
 *
 * FO-3 のウィンドウは、資源（スキーマ URL / `vct` / `schema_uri`）の取得に成功した時点で破棄する。
 * その後に再び取得に失敗した場合は、設定した時間上限で計測を再開する。
 * `applySchemaViolations` の成功パス（`result.valid` かつ違反 0 件）は FO-4 が使う
 * `violationKey`（資源キー + {@link credentialFingerprint}）しか破棄できないため、呼び出し側
 * （`credential-schema/validate.ts` / `sdjwt/type-metadata/resolve.ts`）は資源の取得に成功した
 * 直後にこの関数で FO-3 が使う資源キー（`w3c:<url>` / `sdjwt-vct:<vct>` / `sdjwt-schema:<uri>`）を
 * 明示的に破棄する。
 *
 * `resolveWindow` と同じ形状検証を経由するため、不正な形状の `failOpenWindow` が注入されていても
 * 例外にならず黙ってスキップする（`window-guard.test.ts` と同じ規律）。
 *
 * @param key 破棄する資源キー。
 * @param options ウィンドウを含む fail-safe オプション。
 */
export function clearFailOpenWindow(key: string, options: SchemaFailSafeGateOptions): void {
  resolveWindow(options)?.clear(key);
}

/**
 * 検証対象クレームから Fail-open ウィンドウのキーへ足す指紋を作る。
 *
 * FO-4（任意属性違反）の時間上限は**スキーマ資源単位ではなくクレデンシャル単位**に近づける
 * 資源単位のキーのみだと、同じスキーマを参照する**無関係な別の
 * クレデンシャル**がたまたま綺麗に通っただけで（`applySchemaViolations` の clear）、違反している
 * クレデンシャル側の Fail-open 予算がリセットされてしまう。
 *
 * 暗号学的な安全性は要らない（監査ログにも出ない、プロセス内メモリのキー分離のみが目的）ため
 * `@noble/hashes` の sha256（`disclosureDigest` と同じ構成）を「安定した短い識別子」として使う。
 * 衝突しても実害は「異なるクレデンシャルが同じ計時ウィンドウを共有してしまう」に留まり、
 * 安全側（deny）への影響は無い。
 *
 * @param payload 検証対象のクレーム（W3C VC の `credentialSubject` / SD-JWT VC の `claims`）。
 * @returns 安定した短い識別子。
 */
export function credentialFingerprint(payload: unknown): string {
  const serialized = JSON.stringify(payload) ?? 'undefined';
  return base64urlnopad.encode(sha256(new TextEncoder().encode(serialized)));
}

/**
 * fail-open ゲート（`resolveFailOpen`）へ委譲する。
 *
 * 任意プロパティは自身のプロパティに限って読む。継承値を素朴に読んで新しい
 * オブジェクトリテラルへ詰め直すと、継承値が own プロパティに化けてゲート側
 * （`failsafe-policy/gate.ts`）の own 限定読み取りを無意味にしてしまう。その結果、fail-safe
 * オプションを一切渡していない検証でもスキーマ未検証のまま通過し、監査レコードが攻撃者の
 * シンクへ渡る。「未設定ならプロパティ自体を生やさない」を保つため、undefined のキーは
 * 条件付き展開で落とす。
 *
 * @param policyEvent FO-3（取得失敗）または FO-4（任意属性違反）。
 * @param key 時間上限を数えるキー（スキーマ URL / `vct`。監査レコードには出さない）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param options 同意・監査記録先・override・ウィンドウ。
 * @returns 許可された場合の警告。許可されなければ undefined。
 */
async function gate(
  policyEvent: FailOpenId,
  key: string,
  nowSeconds: number,
  options: SchemaFailSafeGateOptions,
): Promise<FailSafeWarning | undefined> {
  const window = resolveWindow(options);
  if (window === undefined) {
    // ウィンドウが未指定 / 不正な形状 = 時間上限を計測できない。他の必須条件
    // （同意コールバック・監査記録先）が欠けた場合と同じく Fail-closed に倒す。
    return undefined;
  }
  const policy = ownProperty<SchemaFailSafeGateOptions['failSafePolicy']>(
    options,
    'failSafePolicy',
  );
  const requestConsent = ownProperty<SchemaFailSafeGateOptions['requestConsent']>(
    options,
    'requestConsent',
  );
  const onPolicyEvent = ownProperty<SchemaFailSafeGateOptions['onPolicyEvent']>(
    options,
    'onPolicyEvent',
  );
  const auditContext = ownProperty<SchemaFailSafeGateOptions['auditContext']>(
    options,
    'auditContext',
  );
  return await resolveFailOpen({
    policyEvent,
    window,
    key,
    nowSeconds,
    ...(policy !== undefined ? { policy } : {}),
    ...(requestConsent !== undefined ? { requestConsent } : {}),
    ...(onPolicyEvent !== undefined ? { onPolicyEvent } : {}),
    ...(auditContext !== undefined ? { auditContext } : {}),
  });
}

/**
 * 当該事象が override で Fail-closed に格上げされているかを判定する。
 *
 * 判定は `decideFailSafe`（共通のポリシー判定）に委ね、ここでは
 * 重大度を真偽値へ畳むだけにする。未定義の ID が渡された場合も `decideFailSafe` が
 * 安全側（`deny`）に倒す。
 *
 * **fail-open 事象の判定には使わない。** 同意・監査記録・時間上限を経ない素の格上げ判定なので、
 * 用途は「FO-3 / FO-4 の対象ではないが `escalate` の指定には従いたい」ケース
 * （`credentialSchema` 未宣言 = 3016）に限る。
 *
 * @param policyEvent 判定対象の FO-ID。
 * @param policy SDK 利用者の override（未指定時は事象ごとの既定値を使う）。
 * @returns Fail-closed に倒すべきなら true。
 */
export function isFailClosed(policyEvent: FailOpenId, policy?: FailSafePolicy): boolean {
  return decideFailSafe(policyEvent, policy).severity === 'deny';
}

/**
 * FO-3（スキーマ取得失敗）を fail-open ゲートに通し、通過させる場合の結果を組み立てる。
 *
 * スキーマを取得できていないので `schemaAvailable: false` であり、`valid: true` は
 * 「適合した」ではなく「検証していない」を意味する（`SchemaFailSafeResult` の契約）。
 *
 * @param key 時間上限を数えるキー（経路プレフィックス付きの資源識別子。スキーマ URL / `vct` /
 *            `schema_uri`）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param options 同意・監査記録先・override・ウィンドウ。
 * @returns 通過を許された場合は FO-3 の監査キーを添えた fail-open 結果。許可されなければ
 *          `undefined`（呼び出し側は**元の取得失敗をそのまま伝播する** = Fail-closed）。
 */
export async function schemaFetchFailedResult(
  key: string,
  nowSeconds: number,
  options: SchemaFailSafeGateOptions = {},
): Promise<SchemaFailSafeResult | undefined> {
  const warning = await gate('FO-3', key, nowSeconds, options);
  if (warning === undefined) {
    return undefined;
  }
  return { valid: true, schemaAvailable: false, warnings: [warning.auditEvent] };
}

/**
 * JSON Schema 検証の結果へ FO-4 を適用する。
 *
 * 任意属性の違反（FO-4）は、同意と監査記録が揃う場合に限って警告付きで通過できる。
 *
 * - 違反なし: `valid: true` / 警告なし。加えて**同じ `key` のウィンドウを破棄する**（下記）。
 * - **任意属性のみ**の違反でゲートが許可: `valid: true` + FO-4 の監査キー。違反内容は呼び出し側が
 *   確認できるよう `errors` に残す（通過させたが「何が期待と違ったか」は失わない）。
 * - 任意属性のみの違反でゲートが不許可（同意 / 監査記録先が無い・不同意・記録失敗・`escalate`・
 *   60 秒上限超過）: `valid: false` + 警告なし（Fail-closed）。
 * - **必須属性違反が 1 件でもある**場合: FO-4 の対象外のため、ゲートを通さず常に `valid: false`。
 *
 * **`key` はクレデンシャル単位で計時する**。呼び出し側
 * （`credential-schema/validate.ts` / `sdjwt/type-metadata/resolve.ts`）は資源識別子
 * （スキーマ URL / `vct` / `schema_uri`、経路プレフィックス付き）に {@link credentialFingerprint}
 * を連結した文字列を渡す。資源単位のみのキーだと、同じスキーマを参照する**無関係な別の
 * クレデンシャル**が綺麗に通っただけで違反しているクレデンシャル側の予算がリセットされてしまう
 * ため。破棄するのは**そのクレデンシャルが完全に綺麗に通った場合だけ**（取得に成功し、かつ
 * 違反 0 件）である。
 *
 * **FO-3（資源キー）と FO-4（本関数が扱う `violationKey`）は別キーで独立した 60 秒予算を持つ**
 * 本関数はここで渡された `key`（= `violationKey`）
 * しか破棄しない。資源そのものの取得成功による FO-3 側の資源キーの破棄は、呼び出し側が
 * {@link clearFailOpenWindow} で別途行う（取得成功の時点は「違反 0 件の完全適合」より前に
 * 確定するため、本関数の外側で扱う）。したがって同一クレデンシャルについて取得失敗（FO-3）と
 * 「取得はできるが任意属性が違反する」（FO-4）を交互に繰り返した場合、両者は合算されず、
 * それぞれ独立に最大 60 秒（合計最大 120 秒）まで fail-open を継続しうる。
 *
 * @param key 時間上限を数えるキー（資源識別子 + クレデンシャルの指紋。= `violationKey`）。
 * @param nowSeconds 現在時刻（エポック秒）。
 * @param result JSON Schema 検証の生結果。
 * @param options 同意・監査記録先・override・ウィンドウ。
 * @returns FO-4 を適用した fail-safe 結果。
 */
export async function applySchemaViolations(
  key: string,
  nowSeconds: number,
  result: SchemaValidationResult,
  options: SchemaFailSafeGateOptions = {},
): Promise<SchemaFailSafeResult> {
  if (result.valid) {
    // 検証に成功したら、この violationKey の計時をリセットし、次の
    // 違反を新しい 60 秒で数える。資源キー（FO-3）側の破棄は呼び出し側が {@link clearFailOpenWindow}
    // で別途行うため、ここでは violationKey のみを対象にする。
    // ウィンドウが未指定 / 不正な形状なら安全側に倒し、クリアは黙ってスキップする（クラッシュさせない。
    // 検証自体は既に完全に成功しているため valid: true を返してよい）。
    resolveWindow(options)?.clear(key);
    return { valid: true, schemaAvailable: true, warnings: [] };
  }
  const errors = result.errors ?? [];
  if (errors.some((error) => error.required)) {
    return { valid: false, schemaAvailable: true, errors, warnings: [] };
  }
  const warning = await gate('FO-4', key, nowSeconds, options);
  if (warning === undefined) {
    return { valid: false, schemaAvailable: true, errors, warnings: [] };
  }
  return { valid: true, schemaAvailable: true, errors, warnings: [warning.auditEvent] };
}
