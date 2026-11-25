/**
 * did:plc メソッド実装（PLC ディレクトリ + 署名付き操作ログ）。
 *
 * 解決手順:
 * 1. `GET <directoryUrl>/<did>/log/audit` で当該 DID の全操作（無効化された分岐を含む）を取得し、検証する
 *    （ジェネシスからの DID 再計算・各操作の `sig`・`nullified` と 72 時間の回復窓。`audit-log.ts`）。
 *    最終操作が tombstone なら失効として `2001`。ディレクトリは失効済み DID の文書取得に 410 を返すため、
 *    文書より先に監査ログを取る。
 * 2. `GET <directoryUrl>/<did>` で文書を取得し、有効な操作列から組み立てた文書と一致することを確認する
 *    （不一致は `2010`）。返す文書は組み立てたほう。
 *
 * PLC は `authentication` / `assertionMethod` を出さないため、解決結果ではどちらも既定で空配列になり、VC / VP の
 * 署名検証は fail-closed になる。`relationshipsForKeys` で鍵名ごとに明示した検証関係だけを付ける。
 * `alsoKnownAs` / `services` は値を返すだけで、他サービスとの双方向検証はしない（信頼しない）。
 *
 * 解決先ホストは DID から導出しない（`directoryUrl` は設定値）。解決結果はキャッシュしない（72 時間の回復窓内は鍵が
 * 巻き戻り得るため、呼び出しごとに取得・検証する）。`create` / `update` / `deactivate` は非対応
 * （`METHOD_NOT_SUPPORTED`、code `2002`）で、生成系は独立関数（`lifecycle.ts`）を使う。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に DID・URL・応答本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';
import { verifyAuditLog } from './audit-log.js';
import { assertPlcDid } from './did.js';
import { DEFAULT_PLC_DIRECTORY_URL, directoryBase, getDirectoryJson } from './directory.js';
import {
  assertMatchesDirectoryDocument,
  buildPlcDocument,
  type PlcRelationship,
} from './document.js';
import { isRecord } from './operation.js';

/** `MethodPlc` の構成。 */
export interface MethodPlcConfig {
  /** ディレクトリ。既定 `https://plc.directory`。`https:` のみ。 */
  directoryUrl?: string;
  fetchFn?: typeof fetch;
  /** キー名 → 付与する検証関係。既定は空（`authentication` / `assertionMethod` は空配列）。 */
  relationshipsForKeys?: Readonly<Record<string, readonly PlcRelationship[]>>;
}

const RELATIONSHIPS: readonly string[] = ['authentication', 'assertionMethod'];

/** `relationshipsForKeys` を構成時に 1 度だけ検証して写しを取る。 */
function snapshotRelationships(raw: unknown): Record<string, readonly PlcRelationship[]> {
  const result: Record<string, readonly PlcRelationship[]> = Object.create(null);
  if (raw === undefined) {
    return result;
  }
  if (!isRecord(raw)) {
    throw new VericertsError(ErrorCodes.INVALID_DID, {
      context: { reason: 'invalid_relationships' },
    });
  }
  for (const [name, relationships] of Object.entries(raw)) {
    if (
      !Array.isArray(relationships) ||
      !relationships.every((item) => RELATIONSHIPS.includes(item))
    ) {
      throw new VericertsError(ErrorCodes.INVALID_DID, {
        context: { reason: 'invalid_relationships' },
      });
    }
    result[name] = [...relationships] as PlcRelationship[];
  }
  return result;
}

/**
 * did:plc メソッドプラグイン。`resolve` のみを提供する。
 */
export class MethodPlc implements DIDMethod {
  private readonly directoryUrl: string;
  private readonly fetchFn: typeof fetch | undefined;
  private readonly relationshipsForKeys: Readonly<Record<string, readonly PlcRelationship[]>>;

  /**
   * @param config ディレクトリ・fetch 実装・検証関係の指定（任意）。読み出しは自身のプロパティだけ
   *   （`fetchFn` はプロトタイプメソッド実装を許すため `Object.prototype` 由来だけを除く）。
   * @throws `relationshipsForKeys` が不正（VericertsError、code `2001`、`context.reason: 'invalid_relationships'`）。
   */
  constructor(config: MethodPlcConfig = {}) {
    this.directoryUrl = ownProperty<string>(config, 'directoryUrl') ?? DEFAULT_PLC_DIRECTORY_URL;
    this.fetchFn = nonObjectPrototypeProperty<typeof fetch>(config, 'fetchFn');
    this.relationshipsForKeys = snapshotRelationships(
      ownProperty<unknown>(config, 'relationshipsForKeys'),
    );
  }

  /** メソッド名（`'plc'`）。 */
  method(): string {
    return 'plc';
  }

  /** did:plc の生成は独立関数 `createDidPlc` を使う（code `2002`）。 */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /**
   * did:plc を DID Document に解決する（監査ログを検証する）。
   *
   * @param did did:plc 文字列（`did:plc:` + 小文字 base32 24 文字）。
   * @param scope 解決スコープの予算。取得本文の文字数と監査ログの署名検証の仕事量を計上する。
   * @throws 形式不正・失効（code `2001`）、取得失敗・宛先不正（code `2003`）、
   *         監査ログ・文書の検証失敗（code `2010`、`context.reason` で区分）、予算超過（code `2001`）。
   */
  async resolve(did: string, scope?: ResolutionWorkBudget): Promise<DIDDocument> {
    assertPlcDid(did);
    const base = directoryBase(this.directoryUrl);
    const tip = verifyAuditLog(
      did,
      await getDirectoryJson(`${base}/${did}/log/audit`, this.fetchFn, scope),
      scope,
    );
    if (tip.data === undefined) {
      throw new VericertsError(ErrorCodes.INVALID_DID, { context: { reason: 'plc_deactivated' } });
    }
    const response = await getDirectoryJson(`${base}/${did}`, this.fetchFn, scope);
    if (!isRecord(response)) {
      throw new VericertsError(ErrorCodes.DID_DOC_INVALID);
    }
    const built = buildPlcDocument(did, tip.data, this.relationshipsForKeys);
    assertMatchesDirectoryDocument(built, response);
    return built;
  }

  /** did:plc の更新は独立関数 `updateDidPlc` を使う（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:plc の失効は独立関数 `deactivateDidPlc` を使う（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
