/**
 * コード prefix → カテゴリのマップ。
 * `1`→`key` は errors.ts と同じ対応を使う。
 */
const CATEGORY_BY_PREFIX = {
  1: 'key',
  2: 'did',
  3: 'vc',
  4: 'nonce',
  5: 'trust',
  6: 'storage',
  7: 'aa',
  8: 'protocol',
  9: 'didcomm',
  10: 'eudi',
};

/**
 * コード文字列からカテゴリを判定する。
 * 4 桁は先頭 1 桁、5 桁は先頭 2 桁がカテゴリ prefix。
 * @param {string} code 4-5 桁の数値文字列。
 * @returns {string} カテゴリ名。
 */
export function categoryForCode(code) {
  // 4 桁 = 先頭 1 桁 / 5 桁 = 先頭 2 桁を prefix とする。
  const prefix = code.length === 5 ? Number(code.slice(0, 2)) : Number(code.slice(0, 1));
  const category = CATEGORY_BY_PREFIX[prefix];
  if (category === undefined) {
    throw new Error(`未知のカテゴリ prefix です: code=${code} prefix=${prefix}`);
  }
  return category;
}

/**
 * 2 回以上出現する code を列挙する。
 * @param {object[]} entries エントリ配列。
 * @returns {string[]} 重複している code の配列。
 */
export function findDuplicateCodes(entries) {
  const counts = new Map();
  for (const entry of entries) {
    counts.set(entry.code, (counts.get(entry.code) ?? 0) + 1);
  }
  const duplicates = [];
  for (const [code, count] of counts) {
    if (count >= 2) {
      duplicates.push(code);
    }
  }
  return duplicates;
}

/**
 * 2 回以上出現する name（定数名）を列挙する。
 *
 * code が異なっても name が衝突すると、`ErrorCodes` 定数を実装する際に同名キーが重複する。
 * `findDuplicateCodes` は code 単位のため name 衝突を検知できないので、別途検査する。
 *
 * @param {object[]} entries エントリ配列。
 * @returns {string[]} 重複している name の配列。
 */
export function findDuplicateNames(entries) {
  const counts = new Map();
  for (const entry of entries) {
    counts.set(entry.name, (counts.get(entry.name) ?? 0) + 1);
  }
  const duplicates = [];
  for (const [name, count] of counts) {
    if (count >= 2) {
      duplicates.push(name);
    }
  }
  return duplicates;
}

/**
 * エラーコード一覧を公開レジストリの JSON にまとめる。
 * @param {object[]} entries エントリ配列（レジストリ順）。
 * @returns {object} レジストリオブジェクト。
 */
export function buildRegistryObject(entries) {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    codes: entries,
  };
}

/** 公開レジストリ単体で、Markdown の有無にかかわらず各欄と一意性を検証する。 */
export function validateRegistry(registry) {
  const entries = registry?.codes;
  if (
    registry?.$schema !== 'https://json-schema.org/draft/2020-12/schema' ||
    Object.keys(registry).some((key) => key !== '$schema' && key !== 'codes') ||
    !Array.isArray(entries) ||
    entries.length === 0
  ) {
    throw new Error('error-codes: invalid or empty registry');
  }
  const fields = ['code', 'category', 'name', 'description', 'related_apis', 'fail_safe'];
  for (const entry of entries) {
    if (
      typeof entry?.code !== 'string' ||
      !/^[1-9]\d{3,4}$/.test(entry.code) ||
      entry.category !== categoryForCode(entry.code) ||
      typeof entry.name !== 'string' ||
      !/^[A-Z][A-Z0-9_]*$/.test(entry.name) ||
      typeof entry.description !== 'string' ||
      !entry.description.trim() ||
      !Array.isArray(entry.related_apis) ||
      entry.related_apis.some((api) => typeof api !== 'string' || !api.trim()) ||
      (entry.fail_safe !== undefined &&
        (typeof entry.fail_safe !== 'string' || !/^F[CO]-\d+$/.test(entry.fail_safe))) ||
      Object.keys(entry).some((key) => !fields.includes(key))
    ) {
      throw new Error(`error-codes: invalid registry entry ${entry?.code ?? '(missing code)'}`);
    }
  }
  const duplicates = [...findDuplicateCodes(entries), ...findDuplicateNames(entries)];
  if (duplicates.length > 0)
    throw new Error(`error-codes: duplicate codes or names: ${duplicates.join(', ')}`);
}
