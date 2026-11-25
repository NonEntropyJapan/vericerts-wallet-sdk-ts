/**
 * SD-JWT VC 発行時の Art.9 ガードが **`__proto__` という名前のクレーム**を取り逃さないことの
 * 回帰テスト（エラー `10607`）。
 *
 * `sdjwt/gdpr-guard.ts` は Disclosure をデコードし、`{ [claimName]: value }` 形の単一キー
 * オブジェクトへ詰め直してから走査器へ渡す。この詰め直しを素朴な代入 `holder[claimName] = value`
 * で書くと、`claimName` が `__proto__` のときだけ **own プロパティが作られず holder のプロトタイプが
 * 差し替わる**。走査器 `findSpecialCategoryAttributes` は `Object.getOwnPropertyNames` で own の
 * キーだけを辿るため、そのクレームは走査対象から丸ごと消える。結果として
 * `disclosureClaims: ['__proto__']` に Art.9 属性を詰めた発行が **無検知のまま署名される**。
 * 実装が `Object.defineProperty` を使っているのはこの一点のためであり、素朴な代入へ戻した瞬間に
 * 本ファイルのテストが落ちる（他の Art.9 テストはすべて緑のまま素通りする）。
 *
 * 本ファイルを `sdjwt.gdpr.test.ts` から分けているのは、同ファイルが Linterly のファイル行数上限
 * （300 行）に達しているためである。親ディレクトリ `sdjwt/__tests__/` もディレクトリ行数上限に
 * 近いため、`gdpr/` サブディレクトリ側に置く。
 *
 * 検証内容:
 * - `disclosureClaims: ['__proto__']` に Art.9 属性を入れた発行を `10607` で拒否する（同期・非同期）。
 * - 平文クレーム側（`disclosureClaims: []`）に置いた `__proto__` 経由の Art.9 属性も拒否する。
 * - 対照実験として、無害な値なら `__proto__` は実際に **Disclosure の `claimName`** として送出され、
 *   平文 payload には残らないことを確認する。これが無いと、仮に `__proto__` が Disclosure へ
 *   回らない実装（平文 payload 側で検知）に変わっても上のテストが緑のままになり、
 *   「Disclosure 詰め直しの own プロパティ性」を守っている保証が失われる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt, createSdJwtAsync, parseSdJwt } from '../../sdjwt.js';

const ISSUER_KEY = new Uint8Array(32).fill(23);
const VCT = 'https://example.com/credentials/identity';
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

/**
 * `__proto__` を **own プロパティ**として持つクレームオブジェクトを作る。
 *
 * オブジェクトリテラルに `{ __proto__: value }` と書くと ES の特別扱いでプロトタイプ設定になり、
 * own プロパティにならない（= 攻撃者が実際に送り込む形を再現できずテストが空振りする）。
 * `Object.defineProperty` なら `__proto__` でも通常の own データプロパティになる。
 *
 * @param value `__proto__` クレームの値（ここに Art.9 属性を入れ子で潜ませる）。
 * @returns own の `__proto__` を 1 つだけ持つクレームオブジェクト。
 */
function claimsWithOwnProto(value: unknown): Record<string, unknown> {
  const claims: Record<string, unknown> = {};
  Object.defineProperty(claims, '__proto__', {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  return claims;
}

/** `sign` の呼び出し回数を数える signer（署名鍵に触れる前に倒れることの直接観測用）。 */
function countingSigner(): { signer: CredentialSigner; calls: () => number } {
  const inner = createPrivateKeySigner(ISSUER_KEY, 'ES256');
  let calls = 0;
  return {
    signer: {
      alg: inner.alg,
      publicKeyJwk: inner.publicKeyJwk,
      sign(signingInput: Uint8Array): Uint8Array {
        calls += 1;
        return inner.sign(signingInput);
      },
    },
    calls: () => calls,
  };
}

/** 発行が `10607` で拒否されることを表明する（`toThrow` だけではコードを固定できない）。 */
function expectIssuanceRejected(issue: () => string): void {
  try {
    issue();
    throw new Error('should have thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
  }
}

describe('createSdJwt の Art.9 ガード: __proto__ という名前のクレーム', () => {
  it('開示クレーム名が __proto__ でも入れ子の health を 10607 で拒否する', () => {
    // 本ファイルの核心。Disclosure の詰め直しが素朴な代入だと、この発行が無検知で署名される。
    const { signer, calls } = countingSigner();
    expectIssuanceRejected(() =>
      createSdJwt(signer, {
        vct: VCT,
        disclosureClaims: ['__proto__'],
        claims: claimsWithOwnProto({ health: 'HIV+' }),
      }),
    );
    expect(calls()).toBe(0);
  });

  it('開示クレーム名が __proto__ でも入れ子の diagnosis を 10607 で拒否する（非同期発行）', async () => {
    // 非同期版は独立した関数であり、`buildSdJwtIssuanceParts` の共有が外れると片方が無ガードになる。
    const { signer, calls } = countingSigner();
    const promise = createSdJwtAsync(signer, {
      vct: VCT,
      disclosureClaims: ['__proto__'],
      claims: claimsWithOwnProto({ record: { diagnosis: 'x' } }),
    });
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
    });
    expect(calls()).toBe(0);
  });

  it('平文クレーム側の __proto__ 経由の religion も 10607 で拒否する', () => {
    // 平文側は `sdjwt.ts` が `Object.defineProperty` で payload に載せるため、走査対象の
    // payload JSON に `__proto__` キーとして現れる。開示側とは別経路なので個別に固定する。
    const { signer, calls } = countingSigner();
    expectIssuanceRejected(() =>
      createSdJwt(signer, {
        vct: VCT,
        disclosureClaims: [],
        claims: claimsWithOwnProto({ religion: 'x' }),
      }),
    );
    expect(calls()).toBe(0);
  });

  it('無害な値なら __proto__ は Disclosure の claimName として送出される（対照実験）', () => {
    // 上の開示クレームのケースが「Disclosure を走査したから」拒否されたことの裏付け。
    // `__proto__` が Disclosure へ回らない実装に変わればここが落ち、拒否の根拠が変質したと分かる。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['__proto__'],
      claims: claimsWithOwnProto({ nickname: 'Al' }),
    });
    const { issuerJwt, disclosures } = parseSdJwt(sdJwt);
    const [, payloadSeg = ''] = issuerJwt.split('.');
    const payload = JSON.parse(Buffer.from(payloadSeg, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(payload, '__proto__')).toBe(false);
    expect(disclosures.map((d) => d.claimName)).toEqual(['__proto__']);
  });
});
