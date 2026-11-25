/**
 * スキーマ検証(FO-3 / FO-4)の Fail-open ウィンドウをインスタンスへ閉じ込めるファクトリ。
 *
 * `internal/issuer/status-list-resolver.ts` の `createStatusListResolver`(インスタンスごとに
 * `createFailOpenWindow()` を持つ)と同じパターンを、スキーマ検証の 3 つの入口
 * (`validateClaimsAgainstSchema` / `validateClaimsAgainstCredentialSchema` /
 * `validateClaimsAgainstTypeMetadata`)に適用する。
 *
 * **既定(引数なしで呼んだ場合)は、そのファクトリ呼び出しに閉じたウィンドウを 1 本持つ。**
 * プロセス全体で共有するウィンドウは存在しない(以前の `schema-validation/fail-safe.ts` に
 * あったモジュール共有 `Map` は撤去済み)。アプリケーションは検証の妥当な単位
 * (例: 検証セッション単位・Issuer 信頼設定単位)でインスタンスを作り直すことで、
 * 無関係な検証フロー間の 60 秒計時混線と、計時キー数の上限(既定 256)到達による
 * 恒久的な Fail-open 不能(DoS)の両方を避けられる。
 *
 * `validateClaimsAgainstSchema`(ディスパッチャ)は W3C VC 経路と SD-JWT VC 経路の両方を
 * 選びうるが、`RoutedSchemaValidationOptions` は `failOpenWindow` を経路ごとの入れ子
 * (`typeMetadataOptions` / `credentialSchemaOptions`)でしか受け取らない(両経路を独立させる
 * 設計、`types.ts` 参照)。本ファクトリは同じインスタンスのウィンドウを両方の入れ子へ渡す
 * (経路ごとに別インスタンスを強制しないための利便性で、両経路が同じ資源キー空間を使うことは
 * 経路プレフィックス — `w3c:` / `sdjwt-vct:` / `sdjwt-schema:` — で防いでいる)。
 */

import {
  createFailOpenWindow,
  type FailSafeAuditContext,
  type FailSafeAuditRecord,
  type FailSafeDecision,
  type FailSafePolicy,
} from '../../failsafe-policy/index.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { SchemaFailSafeResult } from '../json-schema/index.js';
import type {
  ResolveTypeMetadataOptions,
  TypeMetadataValidationResult,
} from '../sdjwt/type-metadata/index.js';
import { validateClaimsAgainstTypeMetadata } from '../sdjwt/type-metadata/index.js';
import type { ValidateCredentialSchemaOptions } from '../vc/credential-schema/index.js';
import { validateClaimsAgainstCredentialSchema } from '../vc/credential-schema/index.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { validateClaimsAgainstSchema as dispatchValidateClaimsAgainstSchema } from './dispatch.js';
import type {
  RoutedSchemaValidationOptions,
  RoutedSchemaValidationResult,
  SchemaValidatableCredential,
} from './types.js';

/** `createSchemaValidator` の構築時オプション(インスタンス全体の既定値)。 */
export interface CreateSchemaValidatorOptions {
  /**
   * Fail-open を継続できる最大秒数（既定 60 秒、短縮のみ可）。
   *
   * `createStatusListResolver` と同じく、ウィンドウの生成(＝上限秒数の確定)は構築時の 1 回だけ
   * 行う。個々の検証呼び出しごとに上限を変えることはできない。
   */
  readonly failOpenMaxSeconds?: number;
  /** 既定の fail-safe ポリシーに対する override(呼び出しごとに上書き可能)。 */
  readonly failSafePolicy?: FailSafePolicy;
  /** UI 警告を出しユーザー同意を取るコールバック(呼び出しごとに上書き可能)。 */
  readonly requestConsent?: (decision: FailSafeDecision) => boolean | Promise<boolean>;
  /** Fail-open 判定の監査ログ記録先(呼び出しごとに上書き可能)。 */
  readonly onPolicyEvent?: (record: FailSafeAuditRecord) => void | Promise<void>;
  /** 監査レコードへ付与する相関情報(呼び出しごとに上書き可能)。 */
  readonly auditContext?: FailSafeAuditContext;
}

/** インスタンスへ閉じ込めたウィンドウで動くスキーマ検証器。 */
export interface SchemaValidator {
  /** `dispatch.ts` の `validateClaimsAgainstSchema`(経路自動判定)をこのインスタンスの既定で呼ぶ。 */
  readonly validateClaimsAgainstSchema: (
    credential: SchemaValidatableCredential,
    options?: RoutedSchemaValidationOptions,
  ) => Promise<RoutedSchemaValidationResult>;
  /** `credentialSchema` 経路をこのインスタンスの既定で呼ぶ。 */
  readonly validateClaimsAgainstCredentialSchema: (
    vc: VerifiableCredential,
    options?: ValidateCredentialSchemaOptions,
  ) => Promise<SchemaFailSafeResult>;
  /** Type Metadata 経路をこのインスタンスの既定で呼ぶ。 */
  readonly validateClaimsAgainstTypeMetadata: (
    vct: string,
    claims: Readonly<Record<string, unknown>>,
    options?: ResolveTypeMetadataOptions,
  ) => Promise<TypeMetadataValidationResult>;
}

/** `undefined` のキーを生やさずに条件付きでオブジェクトへ足す(own プロパティ規律を保つ)。 */
function definedEntries<T extends object>(source: T): Partial<T> {
  const result: Partial<T> = {};
  for (const key of Object.keys(source) as (keyof T)[]) {
    const value = source[key];
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * インスタンスに閉じた Fail-open ウィンドウを持つスキーマ検証器を生成する。
 *
 * `createStatusListResolver` と同じ設計: 構築時に 1 本だけ `createFailOpenWindow()` を作り、
 * 以降のすべての呼び出しがそのウィンドウを共有する。呼び出しごとの `options` は本ファクトリの
 * 既定値より優先する(後勝ち)。
 *
 * @param factoryOptions ウィンドウの上限秒数とインスタンス全体の既定値。
 * @returns `validateClaimsAgainstSchema` / `validateClaimsAgainstCredentialSchema` /
 *          `validateClaimsAgainstTypeMetadata` をこのインスタンスの既定で呼べる検証器。
 * @throws `failOpenMaxSeconds` が非負整数でない / 60 秒を超える場合(VericertsError、code `3002`)。
 */
export function createSchemaValidator(
  factoryOptions: CreateSchemaValidatorOptions = {},
): SchemaValidator {
  // 任意プロパティは自身のプロパティに限って読む(共通の理由)。
  // `dispatch.ts` はここより下流で own 限定読み取りを行っているが、本ファクトリが素のプロパティ
  // アクセス(プロトタイプ鎖を辿る)でオプションを読み、新しいオブジェクトリテラルへ詰め直すと、
  // 継承値が own プロパティに化けて下流の own 限定判定が無効化される。`requestConsent` /
  // `onPolicyEvent` は呼び出し側が明示的に渡す任意コールバックであり DI 依存ではないため、
  // `dispatch.ts` と同じく `ownProperty` を使う(プロトタイプメソッドとしての実装を想定しない)。
  const failOpenWindow = createFailOpenWindow(
    ownProperty<number>(factoryOptions, 'failOpenMaxSeconds'),
  );
  const sharedDefaults = definedEntries({
    failSafePolicy: ownProperty<FailSafePolicy>(factoryOptions, 'failSafePolicy'),
    requestConsent: ownProperty<CreateSchemaValidatorOptions['requestConsent']>(
      factoryOptions,
      'requestConsent',
    ),
    onPolicyEvent: ownProperty<CreateSchemaValidatorOptions['onPolicyEvent']>(
      factoryOptions,
      'onPolicyEvent',
    ),
    auditContext: ownProperty<FailSafeAuditContext>(factoryOptions, 'auditContext'),
  });
  const flatDefaults = { ...sharedDefaults, failOpenWindow };

  return {
    async validateClaimsAgainstSchema(credential, options = {}) {
      // 呼び出しごとの経路別オプションも own 限定で読む。スプレッド自体は own プロパティしか
      // 写さないが、スプレッド元をプロトタイプ鎖で読むと、当該オプションを渡していない呼び出しに
      // 攻撃者オブジェクトの中身が丸ごと展開される(`dispatch.ts` と同じ懸念)。
      const typeMetadataOptions = ownProperty<Record<string, unknown>>(
        options,
        'typeMetadataOptions',
      );
      const credentialSchemaOptions = ownProperty<Record<string, unknown>>(
        options,
        'credentialSchemaOptions',
      );
      return await dispatchValidateClaimsAgainstSchema(credential, {
        ...sharedDefaults,
        ...options,
        typeMetadataOptions: { failOpenWindow, ...typeMetadataOptions },
        credentialSchemaOptions: { failOpenWindow, ...credentialSchemaOptions },
      });
    },
    async validateClaimsAgainstCredentialSchema(vc, options = {}) {
      return await validateClaimsAgainstCredentialSchema(vc, { ...flatDefaults, ...options });
    },
    async validateClaimsAgainstTypeMetadata(vct, claims, options = {}) {
      return await validateClaimsAgainstTypeMetadata(vct, claims, { ...flatDefaults, ...options });
    },
  };
}
