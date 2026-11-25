import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { ErrorCodes, VericertsError } from '../../errors.js';

// 公開正本（schemas/error-codes.json）。errors.ts の各定数の name / category が
// このレジストリと一致することを検証する基準に使う（先頭桁ハードコードではなく桁数・ブロック追加に強い）。
// VericertsError 本体のコア振る舞い（instanceof / context / cause 等）は errors.test.ts が担う。
// ここでは ErrorCodes と SSOT の整合性検証のみを対象にする。
// 逆方向（SSOT にあるのに ErrorCodes に無いコードの棚卸し）は
// __tests__/error-codes-registry-drift.test.ts が担う。
const ERROR_CODES_SCHEMA = JSON.parse(
  readFileSync(new URL('../../../../schemas/error-codes.json', import.meta.url), 'utf8'),
) as {
  codes: {
    code: string;
    name: string;
    category: string;
    description: string;
    related_apis: string[];
  }[];
};
const SCHEMA_NAME_BY_CODE = new Map(
  ERROR_CODES_SCHEMA.codes.map((entry) => [entry.code, entry.name]),
);

describe('ErrorCodes ↔ schemas/error-codes.json の定数名整合', () => {
  // SSOT の定数名と errors.ts の ErrorCodes 名が一致することを保証する。
  // 8030 で発生したような定数名の不一致を検出する。gen-error-codes はレジストリ内の整合を検査するため、
  // errors.ts 側の追従漏れはこのテストで検出する。
  test.each(
    Object.entries(ErrorCodes),
  )('ErrorCodes.%s は schema の対応コード名と一致する', (name, code) => {
    expect(SCHEMA_NAME_BY_CODE.get(code)).toBe(name);
  });
});

describe('7xxx Account Abstraction コードの SSOT カバレッジ', () => {
  // ErrorCodes は SSOT 全コードの curated subset（SDK が実際に throw するコードのみ）だが、
  // 7xxx（category=aa）は AA モジュールが専用コードを使うために全件を実装側に持たせる。
  // SSOT（schemas/error-codes.json）の 7xxx を基準に、実装（ErrorCodes / ERROR_REGISTRY）へ
  // 双方向で反映されていることを検証し、今後の 7xxx 追加漏れ・削除・名称/カテゴリドリフトを回帰検知する。
  const AA_CODES = ERROR_CODES_SCHEMA.codes.filter((c) => c.category === 'aa');
  const ERROR_CODE_VALUES = new Set<string>(Object.values(ErrorCodes));

  test('SSOT に 7xxx（aa）コードが存在する（テスト前提の健全性）', () => {
    expect(AA_CODES.length).toBeGreaterThan(0);
    for (const c of AA_CODES) {
      expect(c.code.startsWith('7')).toBe(true);
    }
  });

  test.each(
    AA_CODES.map((c) => [c.code, c.name] as const),
  )('SSOT の aa コード %s (%s) は ErrorCodes に存在し name / category / 構築が一致する', (code, name) => {
    // ErrorCodes への存在（欠落＝実装追従漏れ）。
    expect(ERROR_CODE_VALUES.has(code)).toBe(true);
    // 定数名が SSOT と一致する。
    expect(SCHEMA_NAME_BY_CODE.get(code)).toBe(name);
    // ERROR_REGISTRY 登録済みで new でき、category が SSOT と一致する（実行時 TypeError の回帰検知）。
    const error = new VericertsError(code as (typeof ErrorCodes)[keyof typeof ErrorCodes]);
    expect(error.category).toBe('aa');
    expect(error.message.length).toBeGreaterThan(0);
  });
});

/**
 * 廃番（Deprecated）にしたコード 1 件ぶんの期待値。
 *
 * 廃番の決定はどれも同じ形をしている（SSOT に番号と定数名を予約として残し、説明に
 * `(Deprecated)` を書き、関連 API を空にし、`ErrorCodes` には持たない）。件数ぶんのアサーションを
 * 写経すると同じ `test` が積み上がるので、違う部分（番号・定数名・理由・代替）だけを表に持つ。
 *
 * この表が持つのは**廃番の判断を文書として固定したいコードだけ**で、`(Deprecated)` 印の付いた
 * コード全件の棚卸しは `__tests__/error-codes-registry-drift.test.ts` が SSOT から数え上げて行う。
 */
interface DeprecatedCode {
  /** 予約された番号。 */
  readonly code: string;
  /** SSOT に残す定数名。 */
  readonly name: string;
  /** 廃番の理由と代替（テスト名に出す）。 */
  readonly replacement: string;
}

/**
 * 廃番コードの一覧。
 *
 * 廃番コードを再利用しないよう、番号は予約として
 * registry に残したまま Deprecated 化してある。実装側（`ErrorCodes` / `ERROR_REGISTRY`）には持たない
 * ので `new VericertsError('<code>')` は実行時 TypeError になる。再実装・再追加を回帰検知する。
 *
 * - 2004 DID_FORMAT_INVALID: 2001 INVALID_DID と説明・関連 API が完全に重複し、送出箇所は
 *   0 件だった（`Resolver.methodOf` は形式違反を一貫して 2001 で送出する）。
 * - 2040 DID_DEACTIVATED: did:webvh の `deactivated: true` は
 *   2001 INVALID_DID で送出する（method-webvh.ts。「その識別子ではもう DID Document を
 *   得られない」点で形式違反・未登録と同じ面に寄せる設計判断）。
 * - 2020 DID_CONFIG_MISMATCH: `verifyDIDConfiguration`（wallet/did/facade.ts）は結果
 *   オブジェクトを返す API で、取得・パース・署名検証のいずれの失敗も例外にせず
 *   `DIDConfigurationVerificationResult` へ畳み込む。この API は失敗を例外として伝えない。
 */
const DEPRECATED_CODES: readonly DeprecatedCode[] = [
  {
    code: '2004',
    name: 'DID_FORMAT_INVALID',
    replacement: 'DID 形式違反は 2001 INVALID_DID が担う',
  },
  {
    code: '2040',
    name: 'DID_DEACTIVATED',
    replacement: 'deactivated は 2001 INVALID_DID が担う',
  },
  {
    code: '2020',
    name: 'DID_CONFIG_MISMATCH',
    replacement:
      '紐付けの成否は verifyDIDConfiguration の戻り値（valid / errors / linkedDIDs）で判定する',
  },
];

for (const { code, name, replacement } of DEPRECATED_CODES) {
  describe(`${code} ${name} の廃番`, () => {
    const entry = ERROR_CODES_SCHEMA.codes.find((c) => c.code === code);

    test('SSOT に予約として残り Deprecated 表記を持つ', () => {
      expect(entry).toBeDefined();
      expect(entry?.name).toBe(name);
      expect(entry?.description).toContain('(Deprecated)');
    });

    test('SSOT は関連 API を持たない（どの API からも送出されない）', () => {
      expect(entry?.related_apis).toEqual([]);
    });

    test(`ErrorCodes は ${code} を持たない（${replacement}）`, () => {
      expect(Object.values<string>(ErrorCodes)).not.toContain(code);
    });
  });
}

test('2001 INVALID_DID は廃番コードの代替として存在し続ける', () => {
  expect(ErrorCodes.INVALID_DID).toBe('2001');
});
