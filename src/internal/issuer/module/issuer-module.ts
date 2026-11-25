/**
 * Issuer facade（`IssuerModule`）— Token Status List を用いた VC 発行と失効操作。
 *
 * 本モジュールは 実装済みの運用ヘルパー（`StatusListManager` / `signStatusListToken`）の上に
 * 薄い facade を載せるだけで、ビット列の管理・Token の署名は既存モジュールへ委譲する。facade が
 * 追加で担うのは次の 2 点のみ:
 *
 * 1. VC 発行時のビットインデックス確保と `status` 参照の自動付与（`statusListType` 規則）。
 * 2. `vcId` → 確保済みインデックスの対応付け（`setTokenStatus` が `vcId` で引けるようにする）。
 *
 * `StatusListManager` は呼び出し側が構築して注入する。`uri` / 容量 / ビット幅 / 永続化
 * （`snapshot` / `restore`）を facade が隠すと、**再起動時に `idx` を二重に払い出す**運用事故を
 * 招くためである（`status-list-types.ts` のモジュール JSDoc 参照）。`vcId` → `idx` の対応も同じ理由で
 * 呼び出し側が永続化できるよう `exportEntries` / `importEntries` で出し入れできる。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID・クレーム・URL・インデックス・ビット値・JWT を含めない。
 */

import type { StatusReference } from '../../credential/sdjwt/sdjwt.js';
import type { AnyCredentialSigner } from '../../credential/vc/signer.js';
import type { VerifiableCredential } from '../../credential/vc/vc.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { IssueTokenOptions } from '../status-list-token.js';
import type { StatusPurpose } from '../status-list-types.js';
import type { StatusListManager } from '../token-status-list.js';
import { buildCredential } from './build-vc.js';
import { validateImportedEntries } from './import-entries.js';
import { type IssueOptions, resolveStatusListType } from './issue-options.js';
import { validateIssueInput } from './validate-issue-input.js';

/** `IssuerModule` が扱う Status List の用途。 */
export type TokenStatusPurpose = Extract<StatusPurpose, 'revocation' | 'suspension'>;

/** `status` 参照として VC に載せるリストの優先順（先に見つかったものを採用する）。 */
const PRIMARY_PURPOSE_ORDER: readonly TokenStatusPurpose[] = ['revocation', 'suspension'];

/** `vcId` → purpose ごとの確保済みインデックス（永続化用のスナップショット）。 */
export interface IssuedStatusEntry {
  /** 対象 VC の ID。 */
  readonly vcId: string;
  /** purpose → 確保済みインデックス。 */
  readonly indices: Readonly<Partial<Record<TokenStatusPurpose, number>>>;
}

/** `IssuerModule` の構築オプション。 */
export interface IssuerModuleOptions {
  /** Issuer 識別子（発行する VC の `issuer`）。 */
  readonly issuer: string;
  /**
   * Status List Token の署名鍵。同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`
   * （KMS / HSM 向け `createRemoteSigner`）のいずれも渡せる。
   */
  readonly signer: AnyCredentialSigner;
  /**
   * purpose → Status List。`generateTokenStatusList` / `setTokenStatus` / `issueVC` のビット確保が
   * 対象とするリスト。未設定の purpose を指定した操作は `3018` で拒否する。
   */
  readonly statusLists: Readonly<Partial<Record<TokenStatusPurpose, StatusListManager>>>;
  /** 現在時刻取得関数。既定は `() => new Date()`。テストの決定性のため注入可能。 */
  readonly now?: () => Date;
}

/**
 * Token Status List を用いた VC 発行・失効操作の facade。
 *
 * 状態（`vcId` → 確保済み `idx`）はインスタンスが保持する。プロセスをまたぐ場合は
 * `exportEntries` / `importEntries` と `StatusListManager.snapshot` / `restore` を併せて永続化する。
 */
export class IssuerModule {
  /** Issuer 識別子。 */
  readonly issuer: string;
  /** Status List Token の署名鍵。 */
  private readonly signer: AnyCredentialSigner;
  /** purpose → Status List。 */
  private readonly statusLists: Readonly<Partial<Record<TokenStatusPurpose, StatusListManager>>>;
  /** 現在時刻取得関数。 */
  private readonly now: () => Date;
  /** `vcId` → purpose → 確保済みインデックス。 */
  private readonly entries = new Map<string, Map<TokenStatusPurpose, number>>();

  /**
   * @param opts issuer / signer / statusLists / now。
   * @throws `issuer` が空文字の場合（VericertsError、code `3002`）。
   */
  constructor(opts: IssuerModuleOptions) {
    if (opts.issuer.length === 0) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    // 構築時オプションも自身のプロパティに限って読む。同クラスの `issueVC` は
    // `issuanceDate` を own 化済みなのに、ここが鎖読みのままだと**汚染だけで署名済み VC の
    // `issuanceDate`（= JWT-VC の `nbf`）が攻撃者の時刻になる**。`signer` / `statusLists` は
    // 関数・オブジェクトを prototype で公開する正当な実装があり得るため
    // `nonObjectPrototypeProperty` を使う。
    this.issuer = opts.issuer;
    this.signer = nonObjectPrototypeProperty<IssuerModuleOptions['signer']>(
      opts,
      'signer',
    ) as IssuerModuleOptions['signer'];
    this.statusLists = nonObjectPrototypeProperty<IssuerModuleOptions['statusLists']>(
      opts,
      'statusLists',
    ) as IssuerModuleOptions['statusLists'];
    this.now = nonObjectPrototypeProperty<() => Date>(opts, 'now') ?? ((): Date => new Date());
  }

  /**
   * Holder DID とクレームから VC を組み立てる。
   *
   * `statusListType`が `token-status-list` で `opts.credentialStatus !== false` のとき、
   * 設定済みの各 Status List からインデックスを 1 つずつ確保し、`status` に
   * `{ status_list: { idx, uri } }` を自動付与する。`status` が指す先は `revocation` リスト
   * （未設定なら `suspension` リスト）で、Token Status List の `status` クレームが単一参照しか
   * 持てないためである。他 purpose のインデックスも確保・記録されるので `setTokenStatus` で引ける。
   *
   * 署名・シリアライズは行わない（低レベルプリミティブ `issueCredential` / `createSdJwt` の責務）。
   *
   * 入力検証（Holder DID の形式と Art.9 の特別カテゴリ属性。検査は `claims` に加え、VC へ写る
   * フィールドを持つ `opts` 全体も対象）は `validateIssueInput` が**インデックス確保より前**に
   * 行う。あとで拒否すると確保済み `idx` が宙に浮くためである。
   *
   * `credentialSubject.id` は常に検証済みの `holderDID` になる。`claims.id` を渡しても
   * `holderDID` で上書きされる（DID 形式検査を経ない値による subject 詐称の防止）。
   *
   * `opts.id` に同じ値を渡して 2 回発行すると、`vcId` → 確保済みインデックスの対応は後の発行で
   * 上書きされる。先に発行した VC のインデックスは `setTokenStatus` から辿れなくなる（＝失効
   * 操作が効かない）ため、`opts.id` は VC ごとに一意な値を渡すこと。
   *
   * @param holderDID VC の保持者 DID（`credentialSubject.id`）。
   * @param claims VC のクレーム（`credentialSubject` に展開する）。`id` は `holderDID` で上書きする。
   * @param opts 発行オプション（`types` / `format` / `statusListType` / `expirationDate` 等）。
   * @returns 組み立てた W3C VC。
   * @throws Holder DID の形式が不正な場合（VericertsError、code `3006`）、クレームまたは
   *         発行オプション（`evidence` / `termsOfUse` / `refreshService` 等）が Art.9 特別
   *         カテゴリ属性を含む場合（code `10607`）、`format` / `statusListType` が
   *         受理対象外の場合（code `3002`）、Status List の容量を使い切った場合（code `3007`）。
   */
  async issueVC(
    holderDID: string,
    claims: Readonly<Record<string, unknown>>,
    opts: IssueOptions = {},
  ): Promise<VerifiableCredential> {
    // 戻り値のスナップショットを以降で使う（元の `claims` / `opts` を読み直すと、own アクセサが
    // 2 回評価されて検査した値と VC に載る値がずれる。`validate-issue-input.ts` 参照）。
    const safe = validateIssueInput(holderDID, claims, opts);
    const statusListType = resolveStatusListType(safe.opts);
    // `id` / `issuanceDate` は署名済み VC に載る。継承値を拾うと、これらを
    // 指定していない正当な発行でも VC の識別子と発行日が攻撃者の値で署名される。`id` は
    // Status List のインデックス対応にも使われるため、固定値に化けると失効操作が効かなくなる。
    const id = ownProperty<string>(safe.opts, 'id') ?? `urn:uuid:${crypto.randomUUID()}`;
    // 任意プロパティは自身のプロパティに限って読む。`opts.credentialStatus` を
    // プロトタイプ鎖で読むと、`credentialStatus` を**指定していない**正当な発行でも汚染値
    // `false` が「失効管理を付けない」を満たし、`credentialStatus` の無い**失効不能な VC** が
    // 署名される。
    const status =
      statusListType === 'token-status-list' &&
      ownProperty<boolean>(safe.opts, 'credentialStatus') !== false
        ? this.allocateStatus(id)
        : undefined;
    return buildCredential(
      {
        issuer: this.issuer,
        holderDID,
        claims: safe.claims,
        id,
        issuanceDate: ownProperty<string>(safe.opts, 'issuanceDate') ?? this.now().toISOString(),
        ...(status !== undefined ? { status } : {}),
      },
      safe.opts,
    );
  }

  /**
   * 指定用途の Status List Token（JWT）を生成する。
   *
   * 現在のビット列を zlib 圧縮・base64url して `status_list` クレームに載せ、`signer` で署名する。
   * 状態更新（`setTokenStatus`）のあとに再度呼べば**再署名した最新の Token** が得られる。
   *
   * @param purpose Status List の用途（`revocation` / `suspension`）。
   * @param opts Token の `iat` / `exp` / `ttl`。
   * @returns Status List Token（コンパクト JWT 文字列）。
   * @throws 指定用途の Status List が未設定の場合（VericertsError、code `3018`）、
   *         署名演算・外部署名呼び出しが失敗した場合（code `1020`）。
   */
  async generateTokenStatusList(
    purpose: TokenStatusPurpose,
    opts: IssueTokenOptions = {},
  ): Promise<string> {
    return this.requireList(purpose).issueToken(this.signer, opts);
  }

  /**
   * 対象 VC のステータス値を更新する。
   *
   * `issueVC` で確保したインデックスを `vcId` から引き、指定用途のビット列へ `value` を書く。
   * 反映を配信するには更新後に `generateTokenStatusList(purpose)` で Token を再署名する。
   *
   * @param vcId 対象 VC の ID（`issueVC` が返した `vc.id`）。
   * @param purpose Status List の用途（`revocation` / `suspension`）。
   * @param value ステータス値（0 = 有効、bits=1 では 1 = 失効 / 停止）。
   * @throws `vcId` が未登録の場合（VericertsError、code `3070`）、
   *         その VC が指定用途の Status List を持たない場合（code `3018`）、
   *         `value` が値域外の場合（code `3002`）。
   */
  async setTokenStatus(vcId: string, purpose: TokenStatusPurpose, value: number): Promise<void> {
    const indices = this.entries.get(vcId);
    if (indices === undefined) {
      // vcId は例外に含めない。
      throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
    }
    const idx = indices.get(purpose);
    if (idx === undefined) {
      throw new VericertsError(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED);
    }
    this.requireList(purpose).setStatus(idx, value);
  }

  /**
   * `vcId` → 確保済みインデックスの対応を書き出す（永続化用）。
   *
   * `StatusListManager.snapshot` と併せて保存し、再起動時に `importEntries` で復元する。
   *
   * @returns JSON 直列化可能なエントリ配列（登録順）。
   */
  exportEntries(): readonly IssuedStatusEntry[] {
    return [...this.entries].map(([vcId, indices]) => ({
      vcId,
      indices: Object.fromEntries(indices) as IssuedStatusEntry['indices'],
    }));
  }

  /**
   * `exportEntries` で書き出した対応を取り込む。
   *
   * 同じ `vcId` が既にあり**同一内容**なら冪等に受理する。異なるインデックスを持つ重複（既存との衝突、
   * または `entries` 内の重複）は、既存の対応を失って旧 VC が失効不能になるため、何も取り込まずに
   * `3002` で拒否する。同様に、未知 / 未設定の purpose・範囲外 / 非整数の idx・同一 purpose で
   * 別 `vcId`（既存 + 同一バッチ）と重複する idx も、無関係な VC の誤失効や失効不能を招くため
   * 何も取り込まずに `3002` で拒否する（検査は `validateImportedEntries`）。
   *
   * @param entries 復元するエントリ配列。
   * @throws 重複 `vcId` の内容不一致 / 未知 purpose / 範囲外 idx / idx の重複の場合（VericertsError、code `3002`）。
   */
  importEntries(entries: readonly IssuedStatusEntry[]): void {
    // 先に全件を検査して、途中で失敗しても部分取り込みを残さない。
    const incoming = validateImportedEntries(entries, this.entries, this.statusLists);
    for (const [vcId, indices] of incoming) {
      this.entries.set(vcId, indices);
    }
  }

  /**
   * 設定済みの全 Status List からインデックスを確保し、`status` 参照を組み立てる。
   *
   * 設定済みリストのいずれか 1 つでも容量を使い切っていれば、**何も確保せずに** `3007` を送出する
   * （purpose ごとの払い出しをアトミックに扱い、部分確保の漏れを作らない）。
   *
   * @param vcId 対象 VC の ID。登録済みの `vcId` は拒否する（上書きすると旧 VC のインデックスが
   *   孤児になり、`setTokenStatus` から失効・停止できなくなる）。
   * @returns `status` 参照。Status List が 1 つも設定されていない場合は undefined。
   * @throws `vcId` が登録済みの場合（VericertsError、code `3002`）、
   *         Status List の容量を使い切った場合（code `3007`）。
   */
  private allocateStatus(vcId: string): StatusReference | undefined {
    // インデックス消費より前に検査する（拒否した発行で払い出しだけが進む孤児を作らない）。
    if (this.entries.has(vcId)) {
      throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    }
    // 確保は全 purpose まとめて成否を揃える（部分確保の防止）。1 つでも枯渇していれば
    // 何も払い出さずに 3007 を送出する。先に確保してから別リストで失敗すると、そのインデックスは
    // `entries` に載らず巻き戻しもできないため、`setTokenStatus` から永久に辿れない穴になる。
    const lists = PRIMARY_PURPOSE_ORDER.map(
      (purpose) => [purpose, this.statusLists[purpose]] as const,
    ).filter(
      (pair): pair is readonly [TokenStatusPurpose, StatusListManager] => pair[1] !== undefined,
    );
    if (lists.some(([, list]) => list.remaining <= 0)) {
      throw new VericertsError(ErrorCodes.STATUS_LIST_INDEX_EXHAUSTED);
    }
    const indices = new Map<TokenStatusPurpose, number>();
    let primary: StatusReference | undefined;
    for (const [purpose, list] of lists) {
      const entry = list.allocateEntry();
      indices.set(purpose, entry.idx);
      primary ??= entry.status;
    }
    if (indices.size === 0) {
      return undefined;
    }
    this.entries.set(vcId, indices);
    return primary;
  }

  /**
   * 指定用途の Status List を取り出す（未設定なら Token Status List 非対応として拒否）。
   *
   * @param purpose Status List の用途。
   * @returns 対応する `StatusListManager`。
   * @throws 未設定の場合（VericertsError、code `3018`）。
   */
  private requireList(purpose: TokenStatusPurpose): StatusListManager {
    const list = this.statusLists[purpose];
    if (list === undefined) {
      throw new VericertsError(ErrorCodes.TOKEN_STATUS_LIST_UNSUPPORTED);
    }
    return list;
  }
}
