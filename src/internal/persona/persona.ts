/**
 * `PersonaManager` クラス。
 *
 * HD 鍵からペルソナ単位でサブ DID を派生・管理する内部モジュール。導出パスはペルソナ index から決め（新規作成は P-256 =
 * SLIP-0010 `m/9256'/0'/<index>'/0'`。既存の旧レコードだけ secp256k1 = BIP-32 `m/44'/60'/<index>'/0/0`）、その公開鍵から
 * DID（did:key / did:jwk / did:peer）を生成する。既存 DID の取り込み（`registerImportedPersona`）にも使う。
 * 派生メタデータとアクティブ状態は storage に永続化する。
 *
 * 責務分担:
 * - HD 鍵導出は注入された `KeyManager` に、did:key 生成は注入された `createDid` に委譲する。
 *   本クラス固有のロジックは「ペルソナ index → 導出パスの組み立て」「メタデータの採番・永続化」
 *   「アクティブペルソナの管理」「一覧のフィルタ・ソート」に限定する。
 * - 時刻（createdAt / lastUsedAt）は注入された `now` から取得し、決定性とテスト容易性を確保する。
 * - `discardPseudonym` / `isPseudonymDiscarded`・`listDiscardedPseudonyms`は `pseudonym-discard.ts` へ委譲する。
 *
 * セキュリティ上の注意:
 * - メタデータ・例外に seed / privateKey 等の秘密を一切含めない。各委譲先が秘密を含まない
 *   `VericertsError` に正規化済みのため、本クラスはそのまま伝播させる。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { KeyManager } from '../keymanager/keymanager.js';
import { KeyLock } from '../primitives/key-lock.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { decodeMetadata, encodeMetadata } from './codec.js';
import { type CreateDidKeyFn, personaMatchesSeed } from './persona-key.js';
import {
  createPersonaWith,
  type PersonaOpsDeps,
  registerImportedWith,
  restoreLegacyPersonaWith,
} from './persona-ops.js';
import {
  assertPseudonymNotDiscardedIn,
  type DiscardedPseudonym,
  isPseudonymDiscardedIn,
  listDiscardedPseudonymsIn,
  markPseudonymDiscarded,
} from './pseudonym-discard.js';
import { sortPersonas } from './sort.js';
import { notifySwitchListeners } from './switch-notify.js';
import type {
  CreatePersonaOptions,
  ImportPersonaInput,
  ListPersonasOptions,
  PersonaMetadata,
  PersonaSortKey,
  PersonaSwitchListener,
  RestoreLegacyPersonaOptions,
} from './types.js';

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。
 *
 * 循環 import を避けるため `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する。
 */
export interface PersonaStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/**
 * did:key 生成手段。`createDidKey`（method-key.ts）のシグネチャに一致する。
 *
 * テスト容易性のためコンストラクタで注入する。did:jwk / did:peer は DI 不要の純粋関数を直接使う。
 */
export type CreateDidFn = CreateDidKeyFn;

/** storage 上でペルソナメタデータを保存するキーの prefix。 */
const PERSONA_KEY_PREFIX = 'persona/';
/** storage 上でアクティブペルソナ id を保存するキー。 */
const ACTIVE_PERSONA_KEY = 'persona/active';

/**
 * ペルソナ（サブ DID）管理クラス。HD 派生・did:key 生成・永続化を統合する。
 *
 * 状態は storage に永続化されるため、本インスタンス自体はステートレス（注入された依存のみ保持）。
 * `KeyManager` は事前に `importMnemonic` 済みであることを前提とする（未初期化時は委譲先が 1041）。
 */
export class PersonaManager {
  /** アクティブペルソナ切替時に通知するリスナ集合。 */
  private readonly switchListeners = new Set<PersonaSwitchListener>();

  /** ペルソナ作成（採番 → 重複検査 → 永続化）の直列化ロック。 */
  private readonly createLock = new KeyLock();

  /**
   * @param keymanager HD 鍵導出の委譲先（`importMnemonic` 済みを前提）。
   * @param storage メタデータ・アクティブ状態の永続化先。
   * @param createDid did:key 生成手段（既定は method-key.ts の `createDidKey`）。
   * @param now 現在時刻（エポックミリ秒）取得関数。既定は `Date.now`。テスト時に注入する。
   */
  constructor(
    private readonly keymanager: KeyManager,
    private readonly storage: PersonaStorage,
    private readonly createDid: CreateDidFn,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * 新規ペルソナを作成し、メタデータを storage に永続化する。
   *
   * 新規に作成する DID は常に P-256（ES256。SLIP-0010 の `m/9256'/0'/<index>'/0'`）。`method`（`key` / `jwk` / `peer`。
   * 省略時 `key`）だけ選べ、secp256k1 など P-256 以外の `keyType` は作成できない（`1030`。`persona-key.ts`）。
   * index 省略時は既存の最大 index + 1 を採番する。
   *
   * 同じ DID・同じ導出パス（= 同じ鍵）のペルソナが既にあれば `2008`（無言の上書きとペルソナ間の連結を防ぐ）。採番・
   * 重複検査・永続化は直列化され、並行呼び出しでも index 省略時は別 index になる（単一プロセス内のみ）。
   *
   * @param opts 作成オプション（index / label / method / keyType）。
   * @returns 作成されたペルソナのメタデータ。
   * @throws 1041 / 1040 / 1030 / 2008。
   */
  createPersona(opts?: CreatePersonaOptions): Promise<PersonaMetadata> {
    return this.saveBuilt(() => createPersonaWith(this.opsDeps(), opts));
  }

  /**
   * 既存の旧レコード（did:key + secp256k1、BIP-32 `m/44'/60'/<index>'/0/0`）を同じ index で作り直して永続化する。
   * **バックアップ復元など既存データ専用**で、新しい DID の作成には使わない（新規は `createPersona` = P-256 のみ）。
   *
   * @throws 1041 / 1040 / 2008（`createPersona` と同じ）。
   */
  restoreLegacyPersona(opts: RestoreLegacyPersonaOptions): Promise<PersonaMetadata> {
    return this.saveBuilt(() => restoreLegacyPersonaWith(this.opsDeps(), opts));
  }

  /**
   * アクティブペルソナを切り替え、`lastUsedAt` を更新する。
   *
   * 指定 id のメタデータが存在することを確認し、アクティブ id を storage に永続化する。同時に
   * 当該メタデータの `lastUsedAt` を現在時刻へ更新して保存する。永続化が完了した後、登録済みの
   * 切替リスナへ更新済みメタデータを通知する。
   *
   * @param id アクティブにするペルソナ id。
   * @returns 更新後のメタデータ（`lastUsedAt` 反映済み）。
   * @throws 指定 id のペルソナが存在しない場合（VericertsError、code `2005`）。
   */
  async setActivePersona(id: string): Promise<PersonaMetadata> {
    const metadata = await this.requireMetadata(id);
    const updated: PersonaMetadata = { ...metadata, lastUsedAt: this.now() };
    await this.storage.set(this.metadataKey(id), encodeMetadata(updated));
    await this.storage.set(ACTIVE_PERSONA_KEY, new TextEncoder().encode(id));
    notifySwitchListeners(this.switchListeners, updated);
    return updated;
  }

  /**
   * 検証済みの既存 DID をペルソナとして登録する（取り込み。`importPersonaFromDid` が呼ぶ）。
   * DID Document と保持鍵の一致は呼び出し側で確認済みの前提で、ここでは永続化と DID の重複検査のみを行う（`persona-import.ts`）。
   *
   * @throws 2008（同じ DID が既にある）、1040 / 1030 / 1041（`persona-import.ts`）。
   */
  registerImportedPersona(input: ImportPersonaInput): Promise<PersonaMetadata> {
    return this.saveBuilt(() => registerImportedWith(this.opsDeps(), input));
  }

  /** メタデータの組み立て → 保存を、採番・重複検査と同じロック内で行う（作成・復元・取り込みで共通）。 */
  private saveBuilt(build: () => Promise<PersonaMetadata>): Promise<PersonaMetadata> {
    return this.createLock.run(PERSONA_KEY_PREFIX, async () => {
      const metadata = await build();
      await this.storage.set(this.metadataKey(metadata.id), encodeMetadata(metadata));
      return metadata;
    });
  }

  /**
   * 保存済みペルソナが現在の seed から導出した鍵と一致するかを返す（seed 差し替えの検知。
   * 取り込んだ秘密鍵のペルソナは seed に依存しないため `true`）。
   *
   * @throws 導出に失敗した場合（VericertsError、`1040` / `1041`）。
   */
  matchesSeed(persona: PersonaMetadata): Promise<boolean> {
    return personaMatchesSeed(this.keymanager, this.createDid, persona);
  }

  /**
   * アクティブペルソナ切替イベントの通知を購読する。
   *
   * 登録したリスナは `setActivePersona` の永続化完了後に、切替後のメタデータを引数として
   * 同期的に呼び出される。戻り値の関数を呼ぶと購読を解除する。
   *
   * @param listener 切替時に呼び出すリスナ。
   * @returns 購読解除関数（複数回呼んでも安全）。
   */
  onPersonaSwitch(listener: PersonaSwitchListener): () => void {
    this.switchListeners.add(listener);
    return () => {
      this.switchListeners.delete(listener);
    };
  }

  /**
   * 現在アクティブなペルソナのメタデータを返す。
   *
   * アクティブ id が未設定、または参照先メタデータが既に削除されている場合は `null`。
   * 参照先メタデータが storage 上で破損している場合は、`getPersona` 経由で `2005` を伝播する
   * （`null` にはならない）。
   *
   * @returns アクティブペルソナのメタデータ、または未設定時 `null`。
   * @throws 参照先メタデータが破損して復号に失敗した場合（VericertsError、code `2005`）。
   */
  async getActivePersona(): Promise<PersonaMetadata | null> {
    const stored = await this.storage.get(ACTIVE_PERSONA_KEY);
    if (stored === null) {
      return null;
    }
    const id = new TextDecoder().decode(stored);
    return this.getPersona(id);
  }

  /**
   * 指定 id のペルソナメタデータを返す。未存在なら `null`。
   *
   * @param id 取得するペルソナ id。
   * @returns メタデータ、または未存在時 `null`。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `2005`）。
   */
  async getPersona(id: string): Promise<PersonaMetadata | null> {
    const stored = await this.storage.get(this.metadataKey(id));
    if (stored === null) {
      return null;
    }
    return decodeMetadata(stored);
  }

  /**
   * 保存済みペルソナの一覧を返す。任意でラベルフィルタ・ソートを適用する。
   *
   * @param opts フィルタ・ソートオプション（省略時は createdAt 昇順・フィルタなし）。
   * @returns メタデータ配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `2005`）。
   */
  async listPersonas(opts?: ListPersonasOptions): Promise<PersonaMetadata[]> {
    const keys = await this.storage.list(PERSONA_KEY_PREFIX);
    const metadataKeys = keys.filter((key) => key !== ACTIVE_PERSONA_KEY);
    const items: PersonaMetadata[] = [];
    for (const key of metadataKeys) {
      const stored = await this.storage.get(key);
      if (stored !== null) {
        items.push(decodeMetadata(stored));
      }
    }
    const o: object = opts ?? {};
    const label = ownProperty<string>(o, 'label');
    const labelOf = (item: PersonaMetadata) => ownProperty<string>(item, 'label');
    const filtered = label !== undefined ? items.filter((item) => labelOf(item) === label) : items;
    return sortPersonas(
      filtered,
      ownProperty<PersonaSortKey>(o, 'sortBy') ?? 'createdAt',
      ownProperty<'asc' | 'desc'>(o, 'order') ?? 'asc',
    );
  }

  /**
   * 既存メタデータから次に採番すべきペルソナ index（最大 index + 1）を算出する。
   *
   * 既存ゼロ件なら 0 を返す。
   *
   * @returns 次のペルソナ index。
   */
  private async nextIndex(): Promise<number> {
    const personas = await this.listPersonas();
    if (personas.length === 0) {
      return 0;
    }
    const maxIndex = personas.reduce((max, persona) => Math.max(max, persona.index), 0);
    return maxIndex + 1;
  }

  /**
   * 指定 id のメタデータを取得し、未存在なら 2005 を投げる。
   *
   * @param id ペルソナ id。
   * @returns メタデータ。
   * @throws 未存在の場合（VericertsError、code `2005`）。
   */
  private async requireMetadata(id: string): Promise<PersonaMetadata> {
    const metadata = await this.getPersona(id);
    if (metadata === null) {
      throw new VericertsError(ErrorCodes.PERSONA_NOT_FOUND);
    }
    return metadata;
  }

  /** `persona-ops.ts` の手続きへ渡す依存（storage の読み書きと採番を `this` 経由で注入する）。 */
  private opsDeps(): PersonaOpsDeps {
    return {
      keymanager: this.keymanager,
      createDid: this.createDid,
      now: this.now,
      getPersona: (id) => this.getPersona(id),
      listPersonas: () => this.listPersonas(),
      nextIndex: () => this.nextIndex(),
    };
  }

  /** ペルソナ id から storage キーを組み立てる。 */
  private metadataKey(id: string): string {
    return `${PERSONA_KEY_PREFIX}${id}`;
  }

  /**
   * 指定 RP 向けの Pseudonym を「破棄済み」としてマークする。GDPR Art.7(3) の同意撤回時に `GdprFacade.revokeConsent` が呼び出す。
   * 実装は `pseudonym-discard.ts` を参照（鍵の無効化・再生成は行わない。storage のフラグ操作のみ）。
   * RP 識別子（正規化前）が不正なら VericertsError `10201`。
   */
  discardPseudonym(rpIdentifier: string): Promise<void> {
    return markPseudonymDiscarded(this.storage, rpIdentifier, this.now);
  }

  /** 指定 RP 向けの Pseudonym が `discardPseudonym` で破棄済みか（`rpIdentifier` は正規化前。不正なら VericertsError `10201`）。 */
  isPseudonymDiscarded(rpIdentifier: string): Promise<boolean> {
    return isPseudonymDiscardedIn(this.storage, rpIdentifier);
  }

  /** 破棄済み Pseudonym の RP を破棄日時の古い順に一覧で返す（`pseudonym-discard.ts` の `listDiscardedPseudonymsIn`）。 */
  listDiscardedPseudonyms(): Promise<DiscardedPseudonym[]> {
    return listDiscardedPseudonymsIn(this.storage);
  }

  /** 破棄済みの Pseudonym への提示を `10603` で拒否する（実装は `assertPseudonymNotDiscardedIn`）。 */
  assertPseudonymNotDiscarded(rpIdentifier: string): Promise<void> {
    return assertPseudonymNotDiscardedIn(this.storage, rpIdentifier);
  }
}
