/**
 * DelegatedDID の永続化・一覧・ステータス管理を担う `DelegatedDIDStore`。
 *
 * 「自身が controller として指定されている外部 DID」を `did` をキーに storage へ永続化する。
 * 永続化パターンは `persona/persona.ts`（`PersonaManager`）と同じ
 * 「構造的 Storage 依存 + `now` 注入」に揃える。
 *
 * 本ストアは委任関係の **台帳管理** のみを担い、DID ドキュメントの実解決（controller 検証）は
 * 呼び出し側の責務とする（`resolvedAt` / `status` は呼び出し側が解決結果を渡す想定）。
 *
 * セキュリティ上の注意:
 * - レコードは DID / 表示名など公開情報のみを保持する。秘密は一切含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decodeDelegatedDID, encodeDelegatedDID, isDelegationStatus } from './codec.js';
import type { DelegatedDID, DelegationStatus, UpsertDelegatedDIDOptions } from './types.js';

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。
 *
 * 循環 import を避けるため `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する
 * （`persona/persona.ts` の `PersonaStorage` と同パターン）。
 */
interface DelegatedDIDStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** storage 上で DelegatedDID レコードを保存するキーの prefix。 */
const DELEGATED_DID_KEY_PREFIX = 'delegated-did/';

/**
 * DelegatedDID の作成・一覧・ステータス管理を統合する管理クラス。
 *
 * 状態は storage に永続化されるため、本インスタンス自体はステートレス（注入された依存のみ保持）。
 */
export class DelegatedDIDStore {
  /**
   * @param storage レコードの永続化先。
   * @param now 現在時刻取得関数。既定は `() => new Date()`。テスト時に注入する。
   */
  constructor(
    private readonly storage: DelegatedDIDStorage,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /**
   * DelegatedDID を upsert する（`did` をキーに追加または上書き）。
   *
   * `status` 省略時は `"unknown"`、`resolvedAt` 省略時は `now()` を ISO 8601 化する。任意引数は
   * 自身のプロパティに限って読む（`Object.prototype` 汚染で `status` が `active` になるのを防ぐ）。
   * 読み取り側（`decodeDelegatedDID`）が拒否する形のレコードは、永続化すると以後 `list()` が
   * 恒久的に `6005` になるため、永続化前に検査して拒否する。
   *
   * @param input upsert 入力。
   * @returns 永続化したレコード。
   * @throws `did` / `controllerDID` が文字列でない場合（VericertsError、code `2001`）、
   *         `name` / `resolvedAt` が文字列でない・`status` が列挙値外の場合（VericertsError、code `3002`）。
   */
  async upsert(input: UpsertDelegatedDIDOptions): Promise<DelegatedDID> {
    const did = ownProperty<unknown>(input, 'did');
    const controllerDID = ownProperty<unknown>(input, 'controllerDID');
    const name = ownProperty<unknown>(input, 'name');
    const status = ownProperty<unknown>(input, 'status') ?? 'unknown';
    const resolvedAt = ownProperty<unknown>(input, 'resolvedAt') ?? this.now().toISOString();
    if (typeof did !== 'string' || typeof controllerDID !== 'string') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (typeof name !== 'string' || typeof resolvedAt !== 'string' || !isDelegationStatus(status)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const record: DelegatedDID = { did, controllerDID, name, status, resolvedAt };
    await this.storage.set(this.recordKey(record.did), encodeDelegatedDID(record));
    return record;
  }

  /**
   * 保存済みレコードを取得する。未存在なら `null`。
   *
   * @param did 取得する委任 DID。
   * @returns 保存済みレコード、または未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async get(did: string): Promise<DelegatedDID | null> {
    const stored = await this.storage.get(this.recordKey(did));
    return stored === null ? null : decodeDelegatedDID(stored);
  }

  /**
   * 保存済みレコードの一覧を返す。
   *
   * @param controllerDID 指定時は当該 controller のレコードのみに絞り込む。
   * @returns 該当レコードの配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async list(controllerDID?: string): Promise<DelegatedDID[]> {
    const keys = await this.storage.list(DELEGATED_DID_KEY_PREFIX);
    const items: DelegatedDID[] = [];
    for (const key of keys) {
      const stored = await this.storage.get(key);
      if (stored !== null) {
        items.push(decodeDelegatedDID(stored));
      }
    }
    return controllerDID === undefined
      ? items
      : items.filter((item) => item.controllerDID === controllerDID);
  }

  /**
   * レコードのステータスを更新し、`resolvedAt` を現在時刻に更新する。
   *
   * 対象が未存在の場合は `null` を返す no-op（冪等。呼び出し側での存在確認を強制しない）。
   *
   * @param did 対象の委任 DID。
   * @param status 更新後のステータス。
   * @returns 更新後のレコード、または未存在時 `null`。
   * @throws `status` が列挙値外の場合（VericertsError、code `3002`。永続化前に拒否する）、
   *         storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async updateStatus(did: string, status: DelegationStatus): Promise<DelegatedDID | null> {
    if (!isDelegationStatus(status)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const record = await this.get(did);
    if (record === null) {
      return null;
    }
    const updated: DelegatedDID = { ...record, status, resolvedAt: this.now().toISOString() };
    await this.storage.set(this.recordKey(did), encodeDelegatedDID(updated));
    return updated;
  }

  /**
   * レコードを物理削除する。未存在の DID は no-op（冪等）。
   *
   * @param did 削除する委任 DID。
   */
  async remove(did: string): Promise<void> {
    await this.storage.delete(this.recordKey(did));
  }

  /** 委任 DID から storage キーを組み立てる。 */
  private recordKey(did: string): string {
    return `${DELEGATED_DID_KEY_PREFIX}${did}`;
  }
}
