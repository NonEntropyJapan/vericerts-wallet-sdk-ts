/**
 * 公開・発行時に SDK が制限する属性の共通ガード。
 *
 * オンチェーン投下・DID Document 更新時は {@link assertNoSpecialCategoryOnChain} が
 * `10601 GDPR_SPECIAL_CATEGORY_ON_CHAIN` を、VC 発行時は {@link assertNoSpecialCategoryInIssuedContent} が
 * `10607 GDPR_SPECIAL_CATEGORY_ISSUANCE` を送出する（発行はチェーンに書き込まないため）。
 *
 * 属性の判定にはプロパティ名を使う。例外や検出結果には対象の値を含めない。
 *
 * 判定は **正規化名の完全一致** で行う（{@link normalizeAttributeName}）。`birth_date` /
 * `birthDate` / `BirthDate` に加え、JSON-LD の圧縮 IRI（`pid:birth_date`）と展開済み IRI
 * （`https://schema.org/birthDate`）もすべて `birthdate` に畳まれるため、命名規約や
 * JSON-LD の展開状態の違いで検知をすり抜けることはない。部分一致にしないのは誤検知を避けるためで、たとえば `serviceEndpoint`
 * が `race`（`serviceEndpoint` には含まれない）や `id` を含むかどうかで揺れる判定を持ち込まない。
 *
 * 国民識別番号を表す禁止キーは、値に国コードのプレフィックスが付いていても拒否する。
 *
 * 走査対象は **プレーンな JSON 構造（オブジェクトと配列）に限る**。`Map` / `Set` は `Object.keys` に
 * 鍵が現れないため走査されず、`[{ name: 'religion', value: 'x' }]` のような name/value ペア表現も
 * 「`religion` というキー」が存在しないため検知しない。DID Document は JSON なのでこの範囲で足りるが、
 * 汎用の公開前チェックとして使う場合は JSON 相当へ正規化してから渡すこと。
 *
 * 本ガードは網羅的な PII 検出器ではない。既知の Art.9 語彙による fail-safe な足切りであり、
 * 「通過したから個人データを含まない」ことは保証しない。最終的な責務は呼び出し側にある。
 *
 * 誤検知（正当な DID Document の拒否）と検知漏れ（Art.9 属性の公開）では後者の被害が大きく、
 * 公開先が追記専用で取り消せないため、判断に迷う語彙は**残す**側に倒している。誤検知は鍵名を
 * 変えれば回復できるが、公開されたデータは回収できない。
 */

import { ErrorCodes, VericertsError } from './errors.js';
import { toFrozenSetView } from './prototype-safety/frozen-set.js';

/**
 * 属性名を比較用に正規化する（小文字化 + 英数字以外の除去）。
 *
 * `birth_date` / `birthDate` / `birth-date` / `Birth Date` はいずれも `birthdate` になる。
 * JSON-LD の項では圧縮 IRI（`pid:birth_date`）に加えて **展開済み IRI**
 * （`https://schema.org/birthDate` / `http://xmlns.com/foaf/0.1/familyName` /
 * `https://example.org/ns#religion`）もキーとして現れる。区切り文字を落とすだけの正規化では
 * 名前空間部分が残って一致しなくなるため、`:` `/` `#` のいずれか最後に現れた位置より後ろ
 * （= ローカル名）だけを対象にする。名前空間は語彙の同一性に寄与しないので落として構わない。
 *
 * @param name 属性名（プロパティキー）。
 * @returns 正規化済みの属性名。
 */
export function normalizeAttributeName(name: string): string {
  const separator = Math.max(name.lastIndexOf(':'), name.lastIndexOf('/'), name.lastIndexOf('#'));
  const localName = name.slice(separator + 1);
  return localName.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * SDK が公開・発行時に制限する属性の名前。同義語も正規化した形で登録する。
 * 正規化後の形で持つため、ここに `birthdate` と書けば `birth_date` / `birthDate` も一致する。
 */
const SPECIAL_CATEGORY_NAMES: readonly string[] = [
  // 人種・民族
  'race',
  'racialorigin',
  'ethnicity',
  'ethnicorigin',
  // 政治的信条
  'politicalopinion',
  'politicalbelief',
  'politicalaffiliation',
  'politicalparty',
  // 宗教
  'religion',
  'religiousbelief',
  'philosophicalbelief',
  // 労働組合加盟
  'tradeunion',
  'tradeunionmembership',
  // 健康
  'health',
  'healthdata',
  'medicalrecord',
  'medicalhistory',
  'diagnosis',
  'disability',
  // 性的指向
  'sexlife',
  'sexualorientation',
  // 遺伝子・生体情報の生データ
  'geneticdata',
  'dnasequence',
  'dnaprofile',
  'biometricdata',
  'biometrictemplate',
  // 生体情報は「生データ」に限る。`fingerprint` / `iris` / `dna` の裸の語は鍵指紋・
  // 製品名など非 Art.9 の用途が一般的なため採らず、生体データと確定する複合語のみを採る。
  'biometricfingerprint',
  'fingerprintdata',
  'fingerprinttemplate',
  'faceimage',
  'facetemplate',
  'irisscan',
  'irisdata',
  // Pseudo-SSN / 国民識別番号
  'ssn',
  'pseudossn',
  'socialsecuritynumber',
  'nationalid',
  'nationalidentificationnumber',
  'personalidentificationnumber',
  'personaladministrativenumber',
  // PID の生データ
  'familyname',
  'givenname',
  'birthdate',
  'birthplace',
];

/**
 * 禁止属性の語彙（正規化済み・変更不能ビュー）。
 *
 * 判定そのものは module-private な {@link SPECIAL_CATEGORY_LOOKUP} を読むため、この公開ビューを
 * 仮に汚染できたとしても検知範囲は動かない（`frozen-set.ts` 冒頭の 2 段防御を参照）。
 */
export const SPECIAL_CATEGORY_ATTRIBUTES: ReadonlySet<string> =
  toFrozenSetView(SPECIAL_CATEGORY_NAMES);

/** 判定に用いる権威集合（公開ビューとは独立。汚染の影響を受けない）。 */
const SPECIAL_CATEGORY_LOOKUP: ReadonlySet<string> = new Set(SPECIAL_CATEGORY_NAMES);

/**
 * 値が走査対象のオブジェクト（`null` でない object）かを判定する。
 *
 * `Uint8Array` 等の TypedArray やバイナリは「属性名を持たないデータ」であり、数値インデックスを
 * 大量に列挙しても意味がないため走査しない。
 */
function isTraversable(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !ArrayBuffer.isView(value);
}

/**
 * 任意の JSON 的な値を深く走査し、SDK が制限する属性に一致するプロパティ名を集める。
 *
 * 走査は明示スタックによる反復で行う（深い入れ子でスタックオーバーフローを起こさないため）。
 * 循環参照は `WeakSet` で切る。プロパティは **自身のキー**（`Object.getOwnPropertyNames`）を
 * 対象とし、プロトタイプ鎖は辿らない（`Object.prototype` 汚染の値を拾って誤検知しないため。
 * `own-property.ts` の方針と同じ）。
 *
 * **非列挙の own プロパティも走査する。** 呼び出し側が値を読むときに使う `ownProperty` は
 * `Object.hasOwn` 判定であり非列挙でも読むため、走査を `Object.keys`（own かつ列挙可能）に
 * 限ると検査範囲のほうが狭くなる。`Object.defineProperty(o, 'health', { value, enumerable: false })`
 * が検査を素通りして公開・発行される経路になるので、広い側（own 全体）へ揃える。
 *
 * 値は読まない。返すのは一致した属性の **正規化済み名** のみで、個人データは含まれない。
 *
 * @param value 走査対象（DID Document / クレーム等）。
 * @returns 一致した正規化済み属性名（重複なし・辞書順）。一致がなければ空配列。
 */
export function findSpecialCategoryAttributes(value: unknown): readonly string[] {
  const found = new Set<string>();
  const seen = new WeakSet<object>();
  const stack: unknown[] = [value];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!isTraversable(current) || seen.has(current)) {
      continue;
    }
    seen.add(current);

    if (Array.isArray(current)) {
      // 配列の添字は属性名ではないため、要素だけを辿る。スプレッドは巨大配列で
      // `Function.prototype.apply` の引数上限に当たり RangeError になるため使わない。
      for (const item of current) {
        stack.push(item);
      }
      continue;
    }

    for (const key of Object.getOwnPropertyNames(current)) {
      const normalized = normalizeAttributeName(key);
      if (SPECIAL_CATEGORY_LOOKUP.has(normalized)) {
        found.add(normalized);
      }
      stack.push((current as Record<string, unknown>)[key]);
    }
  }

  return [...found].sort();
}

/**
 * 公開先（オンチェーン / IPFS / DID Document）へ出す値に Art.9 特別カテゴリ属性が含まれないことを
 * 表明する。含まれる場合は操作を拒否する。
 *
 * 例外には一致した属性名を載せない。属性名だけでも「その人が健康データを持つ」等を示唆し得るため、
 * `context` に PII を含めない方針に合わせて
 * コードのみを返す。呼び出し側で内訳が必要な場合は {@link findSpecialCategoryAttributes} を使う。
 *
 * @param value 公開予定の値（DID Document / クレーム等）。
 * @throws 禁止属性を含む場合（VericertsError、code `10601`）。
 */
export function assertNoSpecialCategoryOnChain(value: unknown): void {
  if (findSpecialCategoryAttributes(value).length > 0) {
    throw new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN);
  }
}

/**
 * VC に含まれるクレームと発行オプションを検査し、禁止属性を含む場合は発行を拒否する。
 *
 * 名前が `InClaims` ではないのは、検査対象がクレームに閉じないためである。呼び出し側は VC へ写る
 * 発行オプション（`evidence` / `termsOfUse` / `refreshService` 等）もまとめて渡す。個別フィールドを
 * 列挙する設計だと新しいフィールドが増えるたびに検査漏れが生まれるため、対象は「呼び出し側由来で
 * VC に載る値の集合」として渡す約束にしている。
 *
 * 発行時は `10607 GDPR_SPECIAL_CATEGORY_ISSUANCE`、オンチェーン向けの検査は
 * {@link assertNoSpecialCategoryOnChain} で `10601` を送出する。
 *
 * 例外には一致した属性名を載せない。属性名だけでも「その人が健康データを持つ」等を示唆し得るため、
 * `context` に PII を含めない方針に合わせてコードのみを
 * 返す。呼び出し側で内訳が必要な場合は {@link findSpecialCategoryAttributes} を使う。
 *
 * @param payloads 発行予定の内容（クレーム、および発行オプションのように VC に載る値）。配列で
 *                 まとめて渡してよい（走査器は配列の添字を属性名として扱わない）。
 * @throws 禁止属性を含む場合（VericertsError、code `10607`）。
 */
export function assertNoSpecialCategoryInIssuedContent(payloads: unknown): void {
  if (findSpecialCategoryAttributes(payloads).length > 0) {
    throw new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
  }
}
