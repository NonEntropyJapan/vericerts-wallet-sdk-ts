/**
 * Token Status List のビットインデックス管理と失効（revoke）/ 一時停止（suspend）運用。
 *
 * IETF draft-ietf-oauth-status-list 準拠。
 *
 * 本モジュールは issuer ドメインの責務として以下を担う:
 * - Status List のビットインデックス確保（`allocate` / `allocateEntry`）と状態更新
 *   （`setStatus` / `revoke` / `suspend` / `unsuspend`）。
 * - VC へ埋め込む `status` 参照（`StatusReference`）の生成（`reference`）。
 * - Status List Token（JWT）の発行・再発行（`issueToken`。署名は `status-list-token.ts` に委譲）。
 * - 永続化のための状態の書き出し・復元（`snapshot` / `restore`）。
 *
 * ステータス値（bits=1）: 0 = 有効、1 = 失効（revocation）/ 一時停止（suspension）。
 * **`idx` の二重割当を避ける運用手順は `status-list-types.ts` のモジュール JSDoc を参照**。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に URL・インデックス・ビット値・JWT を含めない。
 */

import type { StatusReference } from '../credential/sdjwt/sdjwt.js';
import type { AnyCredentialSigner } from '../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import {
  compressBitstring,
  decompressBitstring,
  type StatusBits,
  StatusBitstring,
} from './bitstring.js';
import { type IssueTokenOptions, signStatusListTokenAsync } from './status-list-token.js';
import {
  type AllocatedStatusEntry,
  STATUS_VALUE_SET,
  STATUS_VALUE_VALID,
  type StatusListManagerOptions,
  type StatusListSnapshot,
  type StatusPurpose,
} from './status-list-types.js';

/**
 * 単一の Status List（特定 URI / purpose）を管理し、Status List Token を発行する。
 *
 * 1 つの `StatusListManager` は 1 本のビット列（1 つの `uri`）に対応する。インデックスは
 * `allocate` / `allocateEntry` で順に確保し、`revoke` / `suspend` / `unsuspend` で状態を更新する。
 */
export class StatusListManager {
  /** Status List Token の参照先 URI。 */
  readonly uri: string;
  /** Issuer 識別子。 */
  readonly issuer: string;
  /** このリストの用途。 */
  readonly purpose: StatusPurpose;
  /** 内部ビット列（`restore` でのみ差し替える）。 */
  private bitstring: StatusBitstring;
  /** 次に確保するインデックス。 */
  private cursor = 0;

  /**
   * @param opts URI / issuer / 容量 / ビット幅 / 用途。
   * @throws size / bits が不正な場合（VericertsError、code `3002`）、
   *         uri / issuer が空文字の場合（code `3002`）。
   */
  constructor(opts: StatusListManagerOptions) {
    if (opts.uri.length === 0 || opts.issuer.length === 0) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    this.uri = opts.uri;
    this.issuer = opts.issuer;
    this.purpose =
      ownProperty<StatusListManagerOptions['purpose']>(opts, 'purpose') ?? 'revocation';
    // size / bits の妥当性検証は StatusBitstring に委譲する。
    this.bitstring = new StatusBitstring(opts.size, ownProperty<StatusBits>(opts, 'bits') ?? 1);
  }

  /** エントリあたりのビット数。 */
  get bits(): StatusBits {
    return this.bitstring.bits;
  }

  /** 収容可能なエントリ数（容量）。 */
  get size(): number {
    return this.bitstring.size;
  }

  /** 次に払い出されるインデックス（= これまでに払い出した数）。 */
  get nextIndex(): number {
    return this.cursor;
  }

  /** 残りの割当可能数（0 なら次の `allocate` は 3007 を投げる）。 */
  get remaining(): number {
    return this.bitstring.size - this.cursor;
  }

  /**
   * 新しいビットインデックスを 1 つ確保する（VC 発行時に呼ぶ）。
   *
   * 払い出しは単調増加で、解放済みインデックスの再利用は行わない。
   *
   * @returns 確保したインデックス（0 始まり）。
   * @throws 容量を使い切った場合（VericertsError、code `3007` STATUS_LIST_INDEX_EXHAUSTED）。
   */
  allocate(): number {
    if (this.cursor >= this.bitstring.size) {
      throw new VericertsError(ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED);
    }
    const index = this.cursor;
    this.cursor += 1;
    return index;
  }

  /**
   * インデックスを確保し、VC へ埋め込む `status` 参照まで組み立てて返す。
   *
   * @returns 確保した `idx` と `status` 参照。
   * @throws 容量を使い切った場合（VericertsError、code `3007`）。
   */
  allocateEntry(): AllocatedStatusEntry {
    const idx = this.allocate();
    return { idx, status: this.reference(idx) };
  }

  /**
   * 指定インデックスのステータス値を設定する（bits > 1 の任意値を書くための低レベルな脱出口）。
   *
   * `revoke` / `suspend` / `unsuspend` の purpose ガードと不可逆性の保証は**適用されない**
   * （`revocation` リストでも 0 を書き戻せる）。用途が明確な場合はそれらのメソッドを使う。
   *
   * @param index `allocate` で確保したインデックス。
   * @param value ステータス値（0 = 有効、bits=1 では 1 = 失効/停止）。
   * @throws index が容量外 / value が値域外の場合（VericertsError、code `3002`）。
   */
  setStatus(index: number, value: number): void {
    this.bitstring.set(index, value);
  }

  /**
   * 指定インデックスの現在のステータス値を読み取る。
   *
   * @param index `allocate` で確保したインデックス。
   * @returns ステータス値。
   * @throws index が容量外の場合（VericertsError、code `3002`）。
   */
  getStatus(index: number): number {
    return this.bitstring.get(index);
  }

  /**
   * 指定インデックスの VC を失効させる（`revocation` リスト専用）。
   *
   * 本メソッド経由では失効は不可逆（取り消す API を持たない）。低レベルな `setStatus` はこの
   * ガードを通らないため、不可逆性は API 全体の不変条件ではない。
   *
   * @param index `allocate` で確保したインデックス。
   * @throws purpose が `revocation` でない / index が容量外の場合（VericertsError、code `3002`）。
   */
  revoke(index: number): void {
    this.assertPurpose('revocation');
    this.bitstring.set(index, STATUS_VALUE_SET);
  }

  /**
   * 指定インデックスの VC を一時停止する（`suspension` リスト専用）。
   *
   * @param index `allocate` で確保したインデックス。
   * @throws purpose が `suspension` でない / index が容量外の場合（VericertsError、code `3002`）。
   */
  suspend(index: number): void {
    this.assertPurpose('suspension');
    this.bitstring.set(index, STATUS_VALUE_SET);
  }

  /**
   * 指定インデックスの一時停止を解除する（`suspension` リスト専用）。
   *
   * `revocation` リストの失効は取り消せないため本メソッドでは扱えない（低レベルな `setStatus`
   * はこのガードを通らない）。
   *
   * @param index `allocate` で確保したインデックス。
   * @throws purpose が `suspension` でない / index が容量外の場合（VericertsError、code `3002`）。
   */
  unsuspend(index: number): void {
    this.assertPurpose('suspension');
    this.bitstring.set(index, STATUS_VALUE_VALID);
  }

  /**
   * 指定インデックスがステータス設定済み（失効 / 停止）かを返す。
   *
   * @param index `allocate` で確保したインデックス。
   * @returns ビット値が 0 以外なら true。
   * @throws index が容量外の場合（VericertsError、code `3002`）。
   */
  isSet(index: number): boolean {
    return this.bitstring.get(index) !== STATUS_VALUE_VALID;
  }

  /**
   * 指定インデックス向けの VC `status` 参照（`StatusReference`）を生成する。
   *
   * @param index `allocate` で確保したインデックス。
   * @returns `{ status_list: { idx, uri } }`。
   */
  reference(index: number): StatusReference {
    return { status_list: { idx: index, uri: this.uri } };
  }

  /**
   * 現在のビット列から Status List Token（コンパクト JWS / JWT）を生成する。
   *
   * 状態更新（`revoke` 等）のあとに再度呼べば**再署名した最新の Token** が得られる。
   *
   * KMS / HSM 向けの `AsyncCredentialSigner`（`createRemoteSigner`）も受け付ける。同期 signer を
   * 渡した場合の出力は従来と完全に一致する（後方互換）。
   *
   * @param signer Issuer の署名鍵（同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`）。
   * @param opts iat / exp / ttl。
   * @returns コンパクト JWT 文字列（`header.payload.signature`）。
   */
  async issueToken(signer: AnyCredentialSigner, opts: IssueTokenOptions = {}): Promise<string> {
    const lst = await compressBitstring(this.bitstring.toBytes());
    return signStatusListTokenAsync(
      { issuer: this.issuer, uri: this.uri, bits: this.bitstring.bits, lst },
      signer,
      opts,
    );
  }

  /**
   * 永続化用の状態（ビット列 + 払い出しカーソル）を書き出す。
   *
   * `allocate` / 状態更新のたびに保存し、再起動時は `restore` で復元する。これを怠ると `idx` を
   * 二重に払い出す（`status-list-types.ts` のモジュール JSDoc 参照）。
   *
   * @returns JSON 直列化可能なスナップショット。
   */
  async snapshot(): Promise<StatusListSnapshot> {
    return {
      uri: this.uri,
      issuer: this.issuer,
      size: this.bitstring.size,
      bits: this.bitstring.bits,
      purpose: this.purpose,
      nextIndex: this.cursor,
      lst: await compressBitstring(this.bitstring.toBytes()),
    };
  }

  /**
   * `snapshot` で書き出した状態から `StatusListManager` を復元する。
   *
   * @param snapshot 永続化していたスナップショット。
   * @returns 復元した `StatusListManager`（`nextIndex` とビット列を引き継ぐ）。
   * @throws スナップショットが不整合な場合（VericertsError、code `3002`）。
   */
  static async restore(snapshot: StatusListSnapshot): Promise<StatusListManager> {
    const manager = new StatusListManager(snapshot);
    if (
      !Number.isInteger(snapshot.nextIndex) ||
      snapshot.nextIndex < 0 ||
      snapshot.nextIndex > snapshot.size
    ) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    const bytes = await decompressBitstring(snapshot.lst);
    // 長さ不整合（size / bits と合わないビット列）は fromBytes が 3002 で弾く。
    manager.bitstring = StatusBitstring.fromBytes(bytes, snapshot.size, snapshot.bits);
    manager.cursor = snapshot.nextIndex;
    return manager;
  }

  /** このリストの用途が期待どおりかを検証する（用途分離。本検証を通るメソッドにのみ効く）。 */
  private assertPurpose(expected: StatusPurpose): void {
    if (this.purpose !== expected) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
  }
}

/**
 * 新しい Status List を作成する（`new StatusListManager(...)` の意図が明確な別名）。
 *
 * Issuer Service の「新規 status list を作成する」操作に対応する。
 *
 * @param opts URI / issuer / 容量 / ビット幅 / 用途。
 * @returns 全ビット 0（全て有効）の `StatusListManager`。
 * @throws オプションが不正な場合（VericertsError、code `3002`）。
 */
export function createStatusList(opts: StatusListManagerOptions): StatusListManager {
  return new StatusListManager(opts);
}
