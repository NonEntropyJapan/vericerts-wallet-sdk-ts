/**
 * TrustedIssuerList の永続化・一覧・エントリ管理を担う `TrustedIssuerListStore`。
 *
 * 1 つの `TrustedIssuerList`（手動作成 / W3C CCG TSLv1 インポート / URL 購読のいずれか起点）を単位に
 * storage へ永続化し、`trustedIssuers` 配下のエントリを Issuer DID キーで upsert / 削除する。
 * 永続化パターンは `persona/persona.ts`（`PersonaManager`）と同じ
 * 「構造的 Storage 依存 + `now` / `idGen` 注入」に揃える。
 *
 * 本ストアは Issuer の信頼性を **保持・検索** するのみで、`TrustedIssuerListStore` 自体は
 * VC 検証結果（`isTrustedIssuer` フラグ）を組み立てない。提示検証パイプライン
 * （`credential/presentation/credential-results.ts`）は本ストアから取得した `TrustedIssuerList` を
 * `verifyPresentation({ trustedIssuerList })` の opt-in DI として受け取り、下請けの純関数
 * `isTrustedIssuer`（本ファイル）で内包 VC の `issuerDID` を照合する。
 *
 * セキュリティ上の注意:
 * - レコードは Issuer DID / 表示名など公開情報のみを保持する。秘密は一切含めない。
 */

import { parseIsoDateTimeMs } from '../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { KeyLock } from '../primitives/key-lock.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decodeTrustedIssuerList, encodeTrustedIssuerList } from './codec.js';
import type {
  CreateTrustedIssuerListOptions,
  IsTrustedIssuerOptions,
  TrustedIssuerEntry,
  TrustedIssuerList,
} from './types.js';

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。
 *
 * 循環 import を避けるため `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する
 * （`persona/persona.ts` の `PersonaStorage` と同パターン）。
 */
interface TrustedIssuerListStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** storage 上で TrustedIssuerList レコードを保存するキーの prefix。 */
const TRUSTED_ISSUER_LIST_KEY_PREFIX = 'trusted-issuer-list/';

/**
 * TrustedIssuerList の作成・一覧・エントリ管理を統合する管理クラス。
 *
 * 状態は storage に永続化される。read-modify-write（`addEntry` / `removeEntry`）と `deleteList` は
 * リスト id 単位の `KeyLock` で直列化し、並行呼び出しの lost update（追加の消失・取り消したはずの
 * 信頼エントリの復活 = fail-open）を防ぐ（`BatchCredentialPoolStore` の `poolLock` と同方針。
 * ロックは単一プロセス・同一インスタンス内でのみ有効）。
 */
export class TrustedIssuerListStore {
  private readonly listLock = new KeyLock();

  /**
   * @param storage レコードの永続化先。
   * @param now 現在時刻取得関数。既定は `() => new Date()`。テスト時に注入する。
   * @param idGen リスト ID 採番関数。既定は `crypto.randomUUID`。テスト時に注入する。
   */
  constructor(
    private readonly storage: TrustedIssuerListStorage,
    private readonly now: () => Date = () => new Date(),
    private readonly idGen: () => string = () => crypto.randomUUID(),
  ) {}

  /**
   * 新しい TrustedIssuerList を作成し永続化する。
   *
   * `id` 省略時は `idGen` で採番し、`issuedAt` 省略時は `now()` を ISO 8601 化する。
   * `type` / `version` は仕様固定値（`"TrustedIssuerList"` / `"TSLv1"`）で上書きできない。
   *
   * @param input リスト作成入力。
   * @returns 永続化したリスト。
   */
  async createList(input: CreateTrustedIssuerListOptions): Promise<TrustedIssuerList> {
    // 入力は own 限定で読む。省略したキーが `Object.prototype` の汚染値を拾うと、採番の無効化
    // （`id`）や空のはずのリストへの発行者混入（`trustedIssuers`）が起きる。
    const nextUpdate = ownProperty<string>(input, 'nextUpdate');
    const sourceUrl = ownProperty<string>(input, 'sourceUrl');
    const intervalMs = ownProperty<number>(input, 'intervalMs');
    const listId = ownProperty<string>(input, 'id') ?? this.idGen();
    const initialEntries = ownProperty<TrustedIssuerEntry[]>(input, 'trustedIssuers') ?? [];
    const list: TrustedIssuerList = {
      id: listId,
      type: 'TrustedIssuerList',
      version: 'TSLv1',
      listOperator: input.listOperator,
      listName: input.listName,
      issuedAt: this.now().toISOString(),
      ...(nextUpdate !== undefined ? { nextUpdate } : {}),
      ...(sourceUrl !== undefined ? { sourceUrl } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {}),
      trustedIssuers: initialEntries,
    };
    for (const entry of initialEntries) assertParsableValidity(entry);
    await this.storage.set(this.recordKey(listId), encodeTrustedIssuerList(list));
    return list;
  }

  /**
   * 保存済みリストを取得する。未存在なら `null`。
   *
   * @param id 取得するリストの ID。
   * @returns 保存済みリスト、または未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async getList(id: string): Promise<TrustedIssuerList | null> {
    const stored = await this.storage.get(this.recordKey(id));
    return stored === null ? null : decodeTrustedIssuerList(stored);
  }

  /**
   * 保存済みリストの一覧を返す。
   *
   * @returns 全リストの配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async listLists(): Promise<TrustedIssuerList[]> {
    const keys = await this.storage.list(TRUSTED_ISSUER_LIST_KEY_PREFIX);
    const lists: TrustedIssuerList[] = [];
    for (const key of keys) {
      const stored = await this.storage.get(key);
      if (stored !== null) {
        lists.push(decodeTrustedIssuerList(stored));
      }
    }
    return lists;
  }

  /**
   * リストを物理削除する。未存在の ID は no-op（冪等）。
   *
   * @param id 削除するリストの ID。
   */
  async deleteList(id: string): Promise<void> {
    await this.listLock.run(id, () => this.storage.delete(this.recordKey(id)));
  }

  /**
   * リストへ発行者エントリを upsert する（`entry.id`＝Issuer DID をキーに追加または上書き）。
   *
   * 対象リストが存在しない場合は `null` を返す no-op（冪等。呼び出し側での存在確認を強制しない）。
   *
   * @param listId 対象リストの ID。
   * @param entry 追加・更新する発行者エントリ。
   * @returns 更新後のリスト、またはリスト未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async addEntry(listId: string, entry: TrustedIssuerEntry): Promise<TrustedIssuerList | null> {
    return this.listLock.run(listId, async () => {
      const list = await this.getList(listId);
      if (list === null) {
        return null;
      }
      assertParsableValidity(entry);
      const entryId = entryIssuerId(entry);
      const trustedIssuers = [
        ...trustedIssuersOf(list).filter((existing) => entryIssuerId(existing) !== entryId),
        entry,
      ];
      const updated: TrustedIssuerList = { ...list, trustedIssuers };
      await this.storage.set(this.recordKey(listId), encodeTrustedIssuerList(updated));
      return updated;
    });
  }

  /**
   * リストから発行者エントリを削除する。対象リスト・エントリが未存在なら `null`（冪等）。
   *
   * @param listId 対象リストの ID。
   * @param issuerDid 削除する発行者の DID（`TrustedIssuerEntry.id`）。
   * @returns 更新後のリスト、またはリスト未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async removeEntry(listId: string, issuerDid: string): Promise<TrustedIssuerList | null> {
    return this.listLock.run(listId, async () => {
      const list = await this.getList(listId);
      if (list === null) {
        return null;
      }
      const trustedIssuers = trustedIssuersOf(list).filter(
        (existing) => entryIssuerId(existing) !== issuerDid,
      );
      const updated: TrustedIssuerList = { ...list, trustedIssuers };
      await this.storage.set(this.recordKey(listId), encodeTrustedIssuerList(updated));
      return updated;
    });
  }

  /** 発行者 DID から storage キーを組み立てる。 */
  private recordKey(id: string): string {
    return `${TRUSTED_ISSUER_LIST_KEY_PREFIX}${id}`;
  }
}

/**
 * リストの `trustedIssuers` を own 限定で読む（欠いたリストは空 = 誰も信頼しない。fail-closed）。
 * `isTrustedIssuer` / 索引化 / 更新は呼び出し側が組んだリストも受けるので、継承値（`Object.prototype.trustedIssuers`）で
 * 信頼エントリが混入しないようにする。
 */
export function trustedIssuersOf(list: TrustedIssuerList): readonly TrustedIssuerEntry[] {
  return ownProperty<readonly TrustedIssuerEntry[]>(list, 'trustedIssuers') ?? [];
}

/** エントリの発行者 DID を own 限定で読む。own の文字列でなければ `undefined`。 */
export function entryIssuerId(entry: TrustedIssuerEntry): string | undefined {
  const id = ownProperty<unknown>(entry, 'id');
  return typeof id === 'string' ? id : undefined;
}

/**
 * リスト内に指定 Issuer DID を信頼する有効なエントリがあるかを判定する純関数。
 *
 * `credentialType` 指定時、エントリの `credentialTypes` が定義されていればそれに含まれることを
 * 要求する（未定義のエントリは全種別を対象とみなす）。`validFrom` / `validUntil` は `at`
 * （既定は現在時刻）と ISO 8601 の数値比較で判定する。解釈不能な日付（`validFrom` / `validUntil` /
 * `at`）は fail-closed（false）で扱う。
 *
 * storage I/O を持たないため `mergeWithEbsiPreset` と同様に `TrustedIssuerListStore` から分離し、
 * ストア本体から独立した純関数としてテストできるようにしている。
 *
 * @param list 判定対象のリスト。
 * @param issuerDid 判定する Issuer DID。
 * @param options 対応 VC 種別・基準時刻。
 * @returns 有効な信頼エントリが見つかれば true。
 */
export function isTrustedIssuer(
  list: TrustedIssuerList,
  issuerDid: string,
  options: IsTrustedIssuerOptions = {},
): boolean {
  const at = ownProperty<Date>(options, 'at');
  const credentialType = ownProperty<string>(options, 'credentialType');
  const atMs = (at ?? new Date()).getTime();
  if (!Number.isFinite(atMs)) {
    return false;
  }
  return trustedIssuersOf(list).some((entry) => {
    if (entryIssuerId(entry) !== issuerDid) {
      return false;
    }
    const credentialTypes = ownProperty<readonly string[]>(entry, 'credentialTypes');
    if (
      credentialType !== undefined &&
      credentialTypes !== undefined &&
      !credentialTypes.includes(credentialType)
    ) {
      return false;
    }
    return isWithinValidity(entry, atMs);
  });
}

/**
 * エントリの有効期間（`validFrom` / `validUntil`）が基準時刻 `atMs` を含むか。
 *
 * 解釈不能な日付・オフセット無し/非 ISO の日付（実行環境の TZ で値が変わる）は
 * NaN 比較が常に false となり期間制約が素通りするため、fail-closed（含まない）で扱う。
 * `isTrustedIssuer` と、発行者 DID で索引化した VP 検証側（`entry-result.ts`）が共有する。
 *
 * @param entry 判定対象のエントリ。
 * @param atMs 基準時刻（エポックミリ秒、有限であること）。
 */
/**
 * 解釈できない `validFrom` / `validUntil` を持つエントリを**永続化前に拒否する**。
 *
 * `isWithinValidity` は解釈できない期間を fail-closed で「不一致」とするため、受理して保存すると
 * そのエントリは**何のエラーも警告も出ないまま一生信頼されない**。登録したつもりの発行者の VC が
 * 黙って未検証扱いになり、気づく手段が無い。入口で弾けば呼び出し側が直せる。
 *
 * 受理する形式は `isWithinValidity` の判定と同じ（オフセット必須の厳格な ISO 8601）。日付のみ
 * （`YYYY-MM-DD`）やオフセット無しの日時はここで拒否する。
 */
function assertParsableValidity(entry: TrustedIssuerEntry): void {
  // 期間境界は `isWithinValidity` と同じく own 限定で読む。
  for (const field of ['validFrom', 'validUntil'] as const) {
    const value = ownProperty<string>(entry, field);
    if (value === undefined) continue;
    if (!Number.isFinite(parseIsoDateTimeMs(value))) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID, {
        context: { reason: 'trusted_issuer_validity_unparsable', field },
      });
    }
  }
}

export function isWithinValidity(entry: TrustedIssuerEntry, atMs: number): boolean {
  // 期間境界は own 限定で読む。`validUntil` を持たない（無期限）エントリが汚染値で失効扱いになる、
  // 逆に `validFrom` / `validUntil` を持つはずの検査が汚染で迂回される経路を作らない。
  const validFrom = ownProperty<string>(entry, 'validFrom');
  const validUntil = ownProperty<string>(entry, 'validUntil');
  if (validFrom !== undefined) {
    const fromMs = parseIsoDateTimeMs(validFrom);
    if (!Number.isFinite(fromMs) || fromMs > atMs) {
      return false;
    }
  }
  if (validUntil !== undefined) {
    const untilMs = parseIsoDateTimeMs(validUntil);
    if (!Number.isFinite(untilMs) || untilMs < atMs) {
      return false;
    }
  }
  return true;
}
