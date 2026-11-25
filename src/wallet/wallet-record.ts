/**
 * ウォレットのメタデータを保存する `WalletRecordStore` と、読み出した状態を表す `WalletRecord`。
 * レコードには id / version / createdAt / updatedAt / activePersonaDID / personas が含まれる。
 *
 * 責務分担:
 * - 永続化するのはウォレット同一性の最小サブセット（id / version / createdAt / updatedAt）のみで、
 *   単一キー `wallet/metadata` に UTF-8 JSON で保存する（キー命名は `persona/active` /
 *   `credential/` と同じ prefix 付き規約に従う）。
 * - `activePersonaDID` / `personas` は**永続化しない**。読み取り時に `PersonaManager` の
 *   `getActivePersona` / `listPersonas` へ委譲して都度算出する。ここに複製すると PersonaManager
 *   自身の永続化との二重書き込みになり、整合性ずれ（stale なスナップショット）が生じるため。
 * - 時刻（createdAt / updatedAt）と id 採番は注入された `now` / `idGen` から取得し、決定性と
 *   テスト容易性を確保する（`PersonaManager` と同じ DI パターン）。
 *
 * createdAt / updatedAt はエポックミリ秒。`personas` の各要素は `PersonaMetadata`。
 *
 * 本レコードに秘密（seed / privateKey）は含まれない。それでも decode 失敗は入力（storage 上の
 * 破損データ）由来のため、`internal/persona/codec.ts` と同様に message / cause へ元データを
 * 載せず `VericertsError(6005)` に正規化する。
 */

import { ErrorCodes, VericertsError } from '../internal/errors.js';
import type { PersonaManager } from '../internal/persona/persona.js';
import type { PersonaMetadata } from '../internal/persona/types.js';
import { KeyLock } from '../internal/primitives/key-lock.js';
import { parseJsonWithoutPrototype } from '../internal/prototype-safety/parse-json.js';
import type { Storage } from '../storage/storage.js';

/** storage 上でウォレットルートのメタデータを保存するキー。 */
const WALLET_METADATA_KEY = 'wallet/metadata';

/** 初回作成時に付与するデータスキーマバージョン。 */
const WALLET_SCHEMA_VERSION = '1';

/**
 * ウォレット全体のメタデータ。
 *
 * `wallet/types.ts` の `Wallet`（公開 API ファサード interface）と名前が衝突するため、データ構造側は
 * `WalletRecord` と命名する。
 */
export interface WalletRecord {
  /** ウォレット一意識別子（UUID）。初回作成時に採番し、以後不変。 */
  readonly id: string;
  /** データスキーマバージョン。初回作成時に `'1'`。 */
  readonly version: string;
  /** 作成日時（エポックミリ秒）。以後不変。 */
  readonly createdAt: number;
  /** 最終更新日時（エポックミリ秒）。`touch` で更新する。 */
  readonly updatedAt: number;
  /**
   * 現在アクティブなペルソナの DID。未設定（アクティブペルソナ未選択）なら `null`。
   *
   * `PersonaManager.getActivePersona()` が `null` を返し得るため、空文字で埋めず `null` のまま
   * 表現する。
   */
  readonly activePersonaDID: string | null;
  /** 保有ペルソナの一覧（読み取り時に `PersonaManager.listPersonas()` から算出）。 */
  readonly personas: PersonaMetadata[];
}

/**
 * storage へ永続化するウォレット同一性の最小サブセット。
 *
 * `WalletRecord` のうち `activePersonaDID` / `personas` は永続化対象外（都度 `PersonaManager` から
 * 算出する）のため、本型には含めない。
 */
interface WalletMetadata {
  readonly id: string;
  readonly version: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * ウォレットルートメタデータを storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param metadata 符号化するメタデータ。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
function encodeWalletMetadata(metadata: WalletMetadata): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(metadata));
}

/**
 * storage から取得したバイト列（UTF-8 JSON）をウォレットルートメタデータへ復号する。
 *
 * parse 失敗・必須フィールド欠落はいずれも storage 上の破損とみなし、汎用コード
 * `STORAGE_RECORD_CORRUPTED`(6005) に正規化する（破損＝入力由来のため message / cause には
 * 載せない。`internal/persona/codec.ts` の方針に準拠）。
 *
 * @param bytes `encodeWalletMetadata` が生成したバイト列。
 * @returns 復号されたメタデータ。
 * @throws 破損で parse / 検証に失敗（VericertsError、code `6005`）。
 */
function decodeWalletMetadata(bytes: Uint8Array): WalletMetadata {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  if (!isWalletMetadata(parsed)) {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  return parsed;
}

/**
 * 復号した値が `WalletMetadata` の必須フィールドを満たすかを検証する型ガード。
 *
 * @param value 検証対象（parse 結果）。
 * @returns 必須フィールドが揃っていれば true。
 */
function isWalletMetadata(value: unknown): value is WalletMetadata {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.version === 'string' &&
    typeof v.createdAt === 'number' &&
    typeof v.updatedAt === 'number'
  );
}

/**
 * ウォレットのメタデータを永続化するストア。
 *
 * 状態は storage と `PersonaManager` に委ねるため、本インスタンス自体はステートレス
 * （注入された依存のみ保持）。
 */
export class WalletRecordStore {
  /** メタデータの get → set を直列化するロック（単一プロセス内のみ有効）。 */
  private readonly lock = new KeyLock();

  /**
   * @param storage ルートメタデータの永続化先。
   * @param personas `activePersonaDID` / `personas` の算出委譲先。
   * @param now 現在時刻（エポックミリ秒）取得関数。既定は `Date.now`。テスト時に注入する。
   * @param idGen ウォレット id 採番関数。既定は `crypto.randomUUID`。テスト時に注入する。
   */
  constructor(
    private readonly storage: Storage,
    private readonly personas: PersonaManager,
    private readonly now: () => number = Date.now,
    private readonly idGen: () => string = () => crypto.randomUUID(),
  ) {}

  /**
   * ペルソナの状態と保存済みのメタデータをまとめて返す。
   *
   * 永続化済みメタデータが無ければ初回作成として採番・永続化する（id は `idGen`、version は `'1'`、
   * createdAt / updatedAt は `now()`）。2 回目以降は永続化された id / createdAt をそのまま返す。
   * `activePersonaDID` / `personas` は複製されたスナップショットではなく、呼び出しの都度
   * `PersonaManager` から算出した最新値である。
   *
   * @returns ウォレットルートエンティティ。
   * @throws 永続化済みメタデータが破損して復号に失敗した場合（VericertsError、code `6005`）、
   *         ペルソナメタデータが破損している場合（VericertsError、code `2005`）。
   */
  async get(): Promise<WalletRecord> {
    const metadata = await this.loadOrCreate();
    const active = await this.personas.getActivePersona();
    const personas = await this.personas.listPersonas();
    return {
      ...metadata,
      activePersonaDID: active === null ? null : active.did,
      personas,
    };
  }

  /**
   * `updatedAt` を現在時刻へ更新する（ペルソナ側の変更をルートエンティティへ反映する用途）。
   *
   * 永続化済みメタデータが無ければ `get` と同様に初回作成したうえで更新する。id / version /
   * createdAt は変更しない。
   *
   * @throws 永続化済みメタデータが破損して復号に失敗した場合（VericertsError、code `6005`）。
   */
  async touch(): Promise<void> {
    await this.lock.run(WALLET_METADATA_KEY, async () => {
      const metadata = await this.readOrCreate();
      await this.persist({ ...metadata, updatedAt: this.now() });
    });
  }

  /**
   * 永続化済みのウォレット同一性（id / createdAt）を破棄する。次回の `get` が新しい id を採番する。
   *
   * seed を別のニーモニックへ差し替える復旧経路で、旧ウォレットの id を新 seed のウォレットへ
   * 持ち越さないために使う。
   */
  async reset(): Promise<void> {
    await this.lock.run(WALLET_METADATA_KEY, () => this.storage.delete(WALLET_METADATA_KEY));
  }

  /**
   * 永続化済みメタデータを読み出す。未存在なら初回作成して永続化する。
   * 初回作成（get → idGen → persist）は非原子のため直列化し、並行呼び出しで別 id を返さない。
   *
   * @returns 読み出し済み、または新規作成されたメタデータ。
   * @throws 永続化済みメタデータが破損して復号に失敗した場合（VericertsError、code `6005`）。
   */
  private loadOrCreate(): Promise<WalletMetadata> {
    return this.lock.run(WALLET_METADATA_KEY, () => this.readOrCreate());
  }

  /** {@link loadOrCreate} の本体（`lock` の排他区間内から呼ぶ）。 */
  private async readOrCreate(): Promise<WalletMetadata> {
    const stored = await this.storage.get(WALLET_METADATA_KEY);
    if (stored !== null) {
      return decodeWalletMetadata(stored);
    }
    const timestamp = this.now();
    const created: WalletMetadata = {
      id: this.idGen(),
      version: WALLET_SCHEMA_VERSION,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.persist(created);
    return created;
  }

  /** メタデータを storage へ書き戻す。 */
  private persist(metadata: WalletMetadata): Promise<void> {
    return this.storage.set(WALLET_METADATA_KEY, encodeWalletMetadata(metadata));
  }
}
