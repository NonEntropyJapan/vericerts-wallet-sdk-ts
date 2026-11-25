/**
 * 別ベンダー Wallet Backup コンテナの受理プロファイルとパース。
 *
 * 別ベンダーのコンテナには、この SDK が定める最小受理プロファイルを適用する。IEEE P2958 への
 * 適合性は検証しない。
 *
 * ## なぜコンテナ署名を要求しないのか
 *
 * 本 SDK 自身の `WalletBackup` は `IntegrityProof` でコンテナ全体を覆うが、別ベンダーの
 * コンテナにその署名は存在しない。代わりに受理対象フォーマットの VC は**いずれも発行者
 * 署名で自己検証可能**なため、コンテナ単位ではなく **VC 単位**で暗号検証する（`import-foreign.ts`）。
 *
 * セキュリティ上の注意:
 * - 本コンテナは**本 SDK 自身の署名付きコンテナより信頼度が低い外部入力**である。パースは
 *   `parseJsonWithoutPrototype` を使い、フィールドは `ownProperty` で own 限定に読む。
 * - 形状が受理プロファイルに合致しない場合は fail-closed に 4036 とし、「不明なフィールドは既定値」
 *   のような救済はしない。
 * - 例外メッセージ・context・cause に VC 本文やクレーム値を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';

/**
 * 別ベンダー Wallet Backup コンテナ（本 SDK の最小受理プロファイル）。
 *
 * **公式な IEEE P2958 スキーマではない**（P2958 は Draft で具体スキーマ未公開）。Persona / DID /
 * 設定は本 SDK 固有の概念であり本プロファイルには含めない（VC のみを運ぶ）。
 */
export interface ForeignWalletBackup {
  readonly credentials: readonly ForeignCredentialEntry[];
}

/** 別ベンダーコンテナの VC 1 件。 */
export interface ForeignCredentialEntry {
  /**
   * ベンダーが申告したフォーマット識別子。ここでは受理対象集合へ絞り込まない（受理・拒否の
   * 判定はパースではなくインポート時に行う。受理プロファイルに合わない VC は警告付きスキップの対象であり、
   * パース段階で全体を落とすと部分インポートが成立しないため）。
   */
  readonly format: string;
  /**
   * VC 自身の直列化表現（例: SD-JWT のコンパクト表現）。本 SDK はフォーマット別の検証器へ
   * 渡す以上の解釈をしない。
   */
  readonly data: string;
  /** ベンダー提供の識別子（任意）。復元エントリの `id` に引き継ぐ。 */
  readonly id?: string;
}

/**
 * 受理プロファイルに合致しない形状を 4036 で拒否する（`VericertsError` を組み立てる）。
 *
 * 「どのフィールドが不正か」は返さない。外部コンテナの形状差分を詳細に返すと、受理判定を
 * 探るオラクルになるうえ、フィールド値（VC 本文）が例外へ漏れる経路を作るため。
 */
function incompatible(): VericertsError {
  return new VericertsError(ErrorCodes.W2W_INCOMPATIBLE_VERSION);
}

/**
 * 検証済みの値を `Object.prototype` を継承しないオブジェクトへ詰め直す。
 *
 * `parseJsonWithoutPrototype` が遮断したプロトタイプ鎖を、検証後のオブジェクトリテラルで
 * **復活させない**ために必要である（`parse-json.ts` が「repack」として挙げている漏れ方）。
 * 特に任意項目の `id` は、通常のリテラルへ詰め直すと未指定のエントリで `entry.id` が
 * `Object.prototype.id` の汚染値を拾い、**攻撃者の選んだ ID で VC が復元される**。
 */
function nullProto<T extends object>(value: T): T {
  return Object.assign(Object.create(null) as T, value);
}

/**
 * 配列要素 1 件を `ForeignCredentialEntry` へ検証・正規化する。
 *
 * @param raw パース済みの要素（未検証）。
 * @returns 検証済みエントリ（プロトタイプなし）。
 * @throws 形状不正（VericertsError、code `4036`）。
 */
function toEntry(raw: unknown): ForeignCredentialEntry {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw incompatible();
  }
  const format = ownProperty<unknown>(raw, 'format');
  const data = ownProperty<unknown>(raw, 'data');
  if (typeof format !== 'string' || typeof data !== 'string') {
    throw incompatible();
  }
  const id = ownProperty<unknown>(raw, 'id');
  if (id !== undefined && typeof id !== 'string') {
    throw incompatible();
  }
  return nullProto(id === undefined ? { format, data } : { format, data, id });
}

/**
 * 別ベンダーコンテナの JSON 文字列を検証済みの `ForeignWalletBackup` へパースする。
 *
 * 事前パース済みオブジェクトではなく **JSON 文字列**を受け取るのは、`parseJsonWithoutPrototype`
 * によるプロトタイプ遮断をこの境界で必ず通すためである（呼び出し側が `JSON.parse` で作った
 * オブジェクトを渡せる API にすると、その遮断を迂回できてしまう）。
 *
 * @param containerJson 別ベンダーが生成したコンテナの JSON 文字列（外部入力・低信頼）。
 * @returns 検証済みコンテナ。
 * @throws JSON として解析できない場合、受理プロファイルに合致しない場合
 *         （VericertsError、code `4036`）。
 */
export function parseForeignWalletBackup(containerJson: string): ForeignWalletBackup {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(containerJson);
  } catch {
    // `SyntaxError` の cause は渡さない（コンテナ本文の断片がメッセージに載るため）。
    throw incompatible();
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw incompatible();
  }
  const credentials = ownProperty<unknown>(parsed, 'credentials');
  if (!Array.isArray(credentials)) {
    throw incompatible();
  }
  return nullProto({ credentials: credentials.map(toEntry) });
}
