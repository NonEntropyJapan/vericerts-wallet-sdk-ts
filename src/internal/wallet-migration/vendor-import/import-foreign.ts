/**
 * 別ベンダーの Wallet Backup コンテナを取り込む。
 *
 * `dc+sd-jwt` と `vc+sd-jwt` はエントリごとに検証する。発行者鍵の解決や検証に
 * 1 件でも失敗した場合は `W2W_INTEGRITY_BROKEN`（4033）でインポート全体を拒否する。
 * コンテナの形式を読み取れない場合は `W2W_INCOMPATIBLE_VERSION`（4036）とする。
 *
 * `mso_mdoc` はこの SDK に COSE_Sign1（RFC 9052）の署名検証器がないため復元できない。
 * この場合と未知のフォーマットの場合はそれぞれ理由を警告に記録し、残りのエントリを処理する。
 *
 * 警告にはフォーマットとエントリ ID（なければ添字）だけを含める。クレームや発行者鍵を
 * 開示しないよう、検証エラーには下位例外のメッセージや cause も含めない。
 */

import { verifySdJwt } from '../../credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { nonObjectPrototypeProperty } from '../../prototype-safety/own-property.js';
import type { BackupSourceItem, ImportResult } from '../types.js';
import type { ForeignCredentialEntry } from './container.js';
import { parseForeignWalletBackup } from './container.js';

/** SD-JWT VC として署名を検証するフォーマット。 */
const SD_JWT_FORMATS: ReadonlySet<string> = new Set(['dc+sd-jwt', 'vc+sd-jwt']);

/** mdoc として識別して、署名検証器が未実装である理由を警告するフォーマット。 */
const MSO_MDOC_FORMAT = 'mso_mdoc';

/** `importForeignBackup` の依存注入。 */
export interface ImportForeignBackupDependencies {
  /**
   * SD-JWT VC エントリ 1 件の発行者検証鍵を解決する。**必須**。
   *
   * 本 SDK 内部の DID 解決器（`wallet/issuer-key.ts` の `resolveSdJwtIssuerKey`）を流用しないのは、
   * 別ベンダーの発行者が DID 解決可能とは限らない（x5c / 素の JWK / ローカル信頼リスト等）ため。
   * 鍵の調達方針は呼び出し側の責務とし、本モジュールは `migration.ts` / `lend.ts` と同じ DI 形式で受ける。
   *
   * 解決に失敗（throw / reject）した場合、そのエントリだけを警告でスキップせず
   * **インポート全体を 4033 で拒否する**（検証できない VC を「非準拠フォーマット」と同列に
   * 扱わないため）。
   */
  readonly resolveIssuerKey: (entry: {
    readonly format: string;
    readonly data: string;
  }) => PublicKeyJwk | Promise<PublicKeyJwk>;
}

/** 警告・合成 ID で使うエントリの表示名（ベンダー提供 ID、なければ添字）。 */
function entryLabel(entry: ForeignCredentialEntry, index: number): string {
  return entry.id ?? `#${index}`;
}

/** 復元結果のうち ID 重複したものを検出する（`backup.ts` の同名ロジックと同方針）。 */
function findDuplicateIds(items: readonly BackupSourceItem[]): string[] {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const item of items) {
    if (seen.has(item.id)) {
      dups.add(item.id);
    }
    seen.add(item.id);
  }
  return [...dups];
}

/**
 * SD-JWT VC エントリ 1 件を検証し、復元アイテムへ変換する。
 *
 * 保管時インポート（提示ではない）なので `requireKeyBinding` / `audience` / `nonce` は渡さない。
 * KB-JWT が同梱されていれば `verifySdJwt` が日和見的に検証する。
 *
 * @throws 鍵解決失敗・検証失敗（VericertsError、code `4033`）。
 */
async function restoreSdJwtEntry(
  entry: ForeignCredentialEntry,
  index: number,
  resolveIssuerKey: ImportForeignBackupDependencies['resolveIssuerKey'],
): Promise<BackupSourceItem> {
  try {
    const issuerKey = await resolveIssuerKey({ format: entry.format, data: entry.data });
    verifySdJwt(entry.data, { issuerKey });
  } catch {
    // 失敗理由（3010 / 3024 / 鍵解決の例外 等）は区別せず 4033 へ畳み込む。
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }
  // `format` は**ベンダー申告のまま**引き継ぐ（`VerifiedSdJwt` から導出しない。検証結果には
  // フォーマット識別子の情報がなく、勝手に `dc+sd-jwt` へ正規化すると旧識別子で届いた VC の
  // 由来が失われる）。
  return { id: entry.id ?? `foreign-vc-${index}`, format: entry.format, data: entry.data };
}

/**
 * 別ベンダーが生成した Wallet Backup コンテナを取り込む。
 *
 * 受理プロファイルは本 SDK 独自の最小プロファイル（`container.ts`）であり、公式な IEEE P2958
 * 準拠ではない（P2958 は Draft でコンテナスキーマ未公開）。コンテナ単位の署名は要求せず、
 * 対応する SD-JWT VC を**エントリ単位**で検証する。
 *
 * エントリごとの扱い:
 *
 * | `format`                    | 扱い                                                     |
 * | --------------------------- | -------------------------------------------------------- |
 * | `dc+sd-jwt` / `vc+sd-jwt`   | `verifySdJwt` で検証。成功なら復元、失敗なら**全体拒否** |
 * | `mso_mdoc`                  | スキップ + 警告（COSE 署名検証器が本 SDK に存在しない）  |
 * | それ以外                    | スキップ + 警告（未対応のフォーマット）               |
 *
 * `personas` / `dids` / `settings` は本プロファイルに含まれないため常に空（`summary` の
 * `personaCount` / `didCount` も 0）。
 *
 * @param containerJson 別ベンダーコンテナの JSON 文字列（外部入力・低信頼）。
 * @param deps 発行者検証鍵の解決器（必須）。
 * @returns 復元された VC 群・要約・ID 競合・スキップ理由の警告（エントリ順）。
 * @throws コンテナ形状が受理プロファイル外（VericertsError、code `4036`）/ 準拠フォーマットを
 *         名乗るエントリの検証失敗・発行者鍵の解決失敗・`resolveIssuerKey` 未注入
 *         （code `4033`）。いずれの場合も**部分結果は返さない**。
 */
export async function importForeignBackup(
  containerJson: string,
  deps: ImportForeignBackupDependencies,
): Promise<ImportResult> {
  const container = parseForeignWalletBackup(containerJson);
  // DI は `JSON.parse` を通らないため `parse-json.ts` の遮断が効かない。関数値なので own 限定
  // （`ownProperty`）ではなく `nonObjectPrototypeProperty` で読む（プロトタイプメソッドとして
  // 実装された正当な解決器を弾かないため）。未注入は fail-closed に 4033 とし、「鍵が無いので
  // 全部スキップして警告」へは倒さない（検証を黙って省く経路を作らない）。
  const resolveIssuerKey = nonObjectPrototypeProperty<
    ImportForeignBackupDependencies['resolveIssuerKey']
  >(deps, 'resolveIssuerKey');
  if (typeof resolveIssuerKey !== 'function') {
    throw new VericertsError(ErrorCodes.W2W_INTEGRITY_BROKEN);
  }

  const credentials: BackupSourceItem[] = [];
  const warnings: string[] = [];
  for (const [index, entry] of container.credentials.entries()) {
    const label = entryLabel(entry, index);
    if (SD_JWT_FORMATS.has(entry.format)) {
      credentials.push(await restoreSdJwtEntry(entry, index, resolveIssuerKey));
      continue;
    }
    if (entry.format === MSO_MDOC_FORMAT) {
      warnings.push(
        `mso_mdoc entry ${label}: skipped — COSE signature verification not yet implemented in this SDK`,
      );
      continue;
    }
    warnings.push(`unsupported format "${entry.format}" for entry ${label}: skipped`);
  }

  return {
    summary: { vcCount: credentials.length, personaCount: 0, didCount: 0 },
    credentials,
    personas: [],
    dids: [],
    conflicts: findDuplicateIds(credentials),
    warnings,
  };
}
