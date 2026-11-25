import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { ErrorCodes, VericertsError } from '../../errors.js';

// 公開正本（schemas/error-codes.json）。errors.ts の各定数の name / category が
// このレジストリと一致することを検証する基準に使う（先頭桁ハードコードではなく桁数・ブロック追加に強い）。
const ERROR_CODES_SCHEMA = JSON.parse(
  readFileSync(new URL('../../../../schemas/error-codes.json', import.meta.url), 'utf8'),
) as { codes: { code: string; name: string; category: string }[] };
const SCHEMA_CATEGORY_BY_CODE = new Map(
  ERROR_CODES_SCHEMA.codes.map((entry) => [entry.code, entry.category]),
);

describe('VericertsError', () => {
  test('instanceof Error かつ instanceof VericertsError、name が VericertsError', () => {
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC);
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(VericertsError);
    expect(error.name).toBe('VericertsError');
  });

  test('1001 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC);
    expect(error.code).toBe('1001');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('BIP-39 ニーモニックが不正です');
  });

  test('1002 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.INVALID_WORD_COUNT);
    expect(error.code).toBe('1002');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('ワード数は 12 または 24 を指定してください');
  });

  test('1003 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
    expect(error.code).toBe('1003');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('秘密鍵フォーマットが不正です');
  });

  test('1004 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.KEY_NOT_FOUND);
    expect(error.code).toBe('1004');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('指定された鍵が見つかりません');
  });

  test('1041 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.MASTER_SEED_NOT_INITIALIZED);
    expect(error.code).toBe('1041');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('マスターシードが初期化されていません');
  });

  test('1020 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.SIGN_FAILED);
    expect(error.code).toBe('1020');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('署名演算に失敗しました');
  });

  test('1030 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
    expect(error.code).toBe('1030');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('未対応のアルゴリズムです');
  });

  test('1040 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
    expect(error.code).toBe('1040');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('不正な BIP-44 導出パスです');
  });

  test('1050 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.DECRYPT_FAILED);
    expect(error.code).toBe('1050');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('復号に失敗しました');
  });

  test('1051 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.ENCRYPT_FAILED);
    expect(error.code).toBe('1051');
    expect(error.category).toBe('key');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('暗号化に失敗しました');
  });

  test('2001 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.INVALID_DID);
    expect(error.code).toBe('2001');
    expect(error.category).toBe('did');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('DID 文字列形式が不正です');
  });

  test('2002 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
    expect(error.code).toBe('2002');
    expect(error.category).toBe('did');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('未対応の DID メソッドです');
  });

  test('2006 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.CONTROLLER_NOT_AUTHORIZED);
    expect(error.code).toBe('2006');
    expect(error.category).toBe('did');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('controller の権限がありません');
  });

  test('2030 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.CONTROLLER_CHAIN_LOOP);
    expect(error.code).toBe('2030');
    expect(error.category).toBe('did');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('controller の循環参照を検出しました');
  });

  test('2011〜2015 は削除済み（ErrorCodes に値として存在しない）', () => {
    const values = Object.values(ErrorCodes) as string[];
    for (const code of ['2011', '2012', '2013', '2014', '2015']) {
      expect(values).not.toContain(code);
    }
  });

  test('3002 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
    expect(error.code).toBe('3002');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC の credentialSchema 必須属性に違反しています');
  });

  test('3010 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.SIG_INVALID);
    expect(error.code).toBe('3010');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC / VP の署名検証に失敗しました');
  });

  test('3011 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.ALG_NONE);
    expect(error.code).toBe('3011');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC / VP のヘッダ alg=none は許可されません');
  });

  test('3020 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.VC_REVOKED);
    expect(error.code).toBe('3020');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC は失効しています');
  });

  test('3024 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.VC_EXPIRED);
    expect(error.code).toBe('3024');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC の有効期限が切れています');
  });

  test('3025 で code / category / retriable / message が解決される', () => {
    const error = new VericertsError(ErrorCodes.VC_NOT_YET_VALID);
    expect(error.code).toBe('3025');
    expect(error.category).toBe('vc');
    expect(error.retriable).toBe(false);
    expect(error.message).toBe('VC はまだ有効化されていません');
  });

  test('context を渡すと保持される', () => {
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC, {
      context: { wordCount: 15 },
    });
    expect(error.context).toEqual({ wordCount: 15 });
  });

  test('context 省略時は undefined', () => {
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC);
    expect(error.context).toBeUndefined();
  });

  test('cause を渡すと error.cause で取得できる', () => {
    const original = new Error('original');
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC, { cause: original });
    expect(error.cause).toBe(original);
  });

  test('cause 省略時は undefined', () => {
    const error = new VericertsError(ErrorCodes.INVALID_MNEMONIC);
    expect(error.cause).toBeUndefined();
  });

  test('ErrorCodes の定数値は数値文字列', () => {
    expect(ErrorCodes.INVALID_MNEMONIC).toBe('1001');
    expect(ErrorCodes.INVALID_WORD_COUNT).toBe('1002');
    expect(ErrorCodes.INVALID_PRIVATE_KEY).toBe('1003');
    expect(ErrorCodes.KEY_NOT_FOUND).toBe('1004');
    expect(ErrorCodes.SIGN_FAILED).toBe('1020');
    expect(ErrorCodes.UNSUPPORTED_ALGORITHM).toBe('1030');
    expect(ErrorCodes.DERIVATION_PATH_INVALID).toBe('1040');
    expect(ErrorCodes.MASTER_SEED_NOT_INITIALIZED).toBe('1041');
    expect(ErrorCodes.DECRYPT_FAILED).toBe('1050');
    expect(ErrorCodes.ENCRYPT_FAILED).toBe('1051');
    expect(ErrorCodes.INVALID_DID).toBe('2001');
    expect(ErrorCodes.METHOD_NOT_SUPPORTED).toBe('2002');
  });

  // ErrorCodes の全値がレジストリに登録され new できることの回帰検知。
  // ErrorCodes と ERROR_REGISTRY のキー集合がズレると、未登録コードの
  // コンストラクタが実行時 TypeError になるため、その追加漏れを検出する。
  test.each(
    Object.values(ErrorCodes),
  )('code %s は new でき code/category/retriable/message を解決する', (code) => {
    const error = new VericertsError(code);
    expect(error.code).toBe(code);
    // category は SSOT（schema）から引く。先頭桁ハードコードだと 10xxx（eudi）等で誤検知するため。
    // 期待値（schema 由来）を actual 側に置き、未登録コード（undefined）も不一致として検出する。
    expect(SCHEMA_CATEGORY_BY_CODE.get(code)).toBe(error.category);
    expect(typeof error.retriable).toBe('boolean');
    // message は秘密を含まない非空の静的文字列。
    expect(error.message.length).toBeGreaterThan(0);
  });
});

// ErrorCodes ↔ SSOT（schemas/error-codes.json）の名称整合・7xxx（Account Abstraction）
// カバレッジは errors.schema-consistency.test.ts に切り出している。
