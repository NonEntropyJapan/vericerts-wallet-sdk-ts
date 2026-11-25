/**
 * 入れ子（深さ 1 以上）の own アクセサに対する深いスナップショット。
 *
 * **トップレベルの** own プロパティについて「検査した値 == 署名済み VC に
 * 載る値」を成立させたが、スナップショットが 1 段の浅い写しだったため、入れ子のオブジェクトが持つ
 * アクセサは参照ごとコピーされて生き残っていた。走査器（`special-category.ts`）は入れ子の
 * own アクセサを**評価しながら**辿るため、
 *
 * 1. 検査時に 1 回目の無害な値が返り、
 * 2. 署名時の `JSON.stringify` が 2 回目を評価して別の値が署名される、
 *
 * というドリフトが深さ 1 以上で成立していた。本ファイルはそのドリフトが**消えている**ことと、
 * 既存の正当な `claims`（`Date` / 循環参照 / 非列挙プロパティ）の扱いが変わっていないことを固定する。
 *
 * `deepSnapshot` 自体の意味論テスト（何を複製し何を参照のまま残すか・記述子・循環参照・
 * 既知の限界）は共有実装を直接叩く `internal/__tests__/deep-snapshot/deep-snapshot.test.ts` にある。
 * 本ファイルは `issueVC` 経路で二重評価ドリフトが成立しないことだけを見る。
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { issueCredential } from '../../../credential/vc/issue.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import { findSpecialCategoryAttributes } from '../../../special-category.js';
import type { IssueOptions } from '../../module/issue-options.js';
import { IssuerModule } from '../../module/issuer-module.js';
import { normalizeClaims } from '../../module/normalized-issue-input.js';
import { createStatusList, type StatusListManager } from '../../token-status-list.js';

const ISSUER = 'did:key:z6MkIssuerNested';
const HOLDER = 'did:key:z6MkHolderNested';
const REVOCATION_URI = 'https://issuer.example/status/revocation';
const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(63), 'ES256');
const IAT = 1_767_225_600;

/** 1 回目と 2 回目で別の値を返す own アクセサを持つ**入れ子の**オブジェクトを作る。 */
function nestedSwappingAccessor(
  key: string,
  first: unknown,
  second: unknown,
): { nested: Record<string, unknown>; reads: () => number } {
  let reads = 0;
  const nested: Record<string, unknown> = {};
  Object.defineProperty(nested, key, {
    get(): unknown {
      reads += 1;
      return reads === 1 ? first : second;
    },
    enumerable: true,
    configurable: true,
  });
  return { nested, reads: () => reads };
}

/**
 * プライベートフィールドを読む**継承**した `toJSON` を持つ `Array` サブクラス。
 *
 * コンストラクタを通さずに複製すると `#label` がインストールされず、`toJSON` が
 * `TypeError: Cannot read private member` で落ちる。深いスナップショットがこの型を
 * 参照のまま残していることを固定するために使う。
 */
class SecretTags extends Array<string> {
  readonly #label: string;

  constructor(label: string, ...items: string[]) {
    super(...items);
    this.#label = label;
  }

  toJSON(): string {
    return `${this.#label}:${this.length}`;
  }
}

/** JWT の payload をデコードする（署名検証はしない）。 */
function payloadOf(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** 署名済み JWT-VC の `vc` クレーム（= 実際に署名されたバイト列が表す VC）を取り出す。 */
function signedVcOf(vc: Awaited<ReturnType<IssuerModule['issueVC']>>): Record<string, unknown> {
  const payload = payloadOf(issueCredential(vc, SIGNER, { nowSeconds: IAT }));
  return payload.vc as Record<string, unknown>;
}

describe('入れ子の own アクセサでも検査値と署名済み VC が一致する', () => {
  let revocation: StatusListManager;
  let issuer: IssuerModule;

  beforeEach(() => {
    revocation = createStatusList({
      uri: REVOCATION_URI,
      issuer: ISSUER,
      size: 64,
      purpose: 'revocation',
    });
    issuer = new IssuerModule({
      issuer: ISSUER,
      signer: SIGNER,
      statusLists: { revocation },
    });
  });

  it('opts.evidence の入れ子アクセサは 1 度しか評価されず、1 回目の値が署名される', async () => {
    // 深いスナップショットを外すと、走査器が 1 回・署名時の `JSON.stringify` が 1 回の計 2 回
    // 評価され、署名済み VC には 2 回目の攻撃者の値が載る（＝このテストが落ちる）。
    const { nested, reads } = nestedSwappingAccessor(
      'evidenceDocument',
      'Passport',
      'AttackerDocument',
    );
    nested.type = 'DocumentVerification';
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, {
      evidence: [nested],
    } as unknown as IssueOptions);
    expect(signedVcOf(vc).evidence).toEqual([
      { evidenceDocument: 'Passport', type: 'DocumentVerification' },
    ]);
    expect(reads()).toBe(1);
  });

  it('claims の入れ子アクセサは 1 度しか評価されず、1 回目の値が署名される', async () => {
    const { nested, reads } = nestedSwappingAccessor('degree', 'BSc', 'PhD');
    const vc = await issuer.issueVC(HOLDER, { profile: nested }, {});
    const subject = signedVcOf(vc).credentialSubject as Record<string, unknown>;
    expect(subject.profile).toEqual({ degree: 'BSc' });
    expect(reads()).toBe(1);
  });

  it('配列の要素より深い位置（深さ 2）のアクセサも畳まれる', async () => {
    const { nested, reads } = nestedSwappingAccessor('degree', 'BSc', 'PhD');
    const vc = await issuer.issueVC(HOLDER, { records: [{ inner: nested }] }, {});
    const subject = signedVcOf(vc).credentialSubject as Record<string, unknown>;
    expect(subject.records).toEqual([{ inner: { degree: 'BSc' } }]);
    expect(reads()).toBe(1);
  });

  it('2 回目に Art.9 属性へすり替わる入れ子アクセサでも、無害な値しか署名されない', async () => {
    // 深いスナップショットが無いと 2 回目の `{ health: 'HIV+' }` が
    // 署名対象に現れ、署名プリミティブ側のガードが 10607 を投げる（＝発行が失敗し、しかも
    // Status List のインデックスは確保済みのまま宙に浮く）。
    const { nested, reads } = nestedSwappingAccessor('detail', { ok: 1 }, { health: 'HIV+' });
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, {
      evidence: [nested],
    } as unknown as IssueOptions);
    const signed = signedVcOf(vc);
    expect(findSpecialCategoryAttributes(signed)).toEqual([]);
    expect(signed.evidence).toEqual([{ detail: { ok: 1 } }]);
    expect(reads()).toBe(1);
  });

  it('プライベートフィールドを読む継承 toJSON を持つ Array サブクラスでも署名まで通る', async () => {
    // 3 周目 major の再発防止テスト。この `Array` サブクラスを複製するとプライベート
    // フィールドが失われ、継承 `toJSON` を呼んだ `JSON.stringify` が素の `TypeError` を投げて
    // 発行そのものが落ちる（Node/V8 で実測。JavaScriptCore は配列の継承 `toJSON` を呼ばない
    // ため Bun では顕在化しない）。Bun でも意味を持つよう、複製されず同一参照であることと
    // `toJSON()` の直接呼び出しが投げないことも併せて固定する。
    const tags = new SecretTags('secret', 'alpha', 'beta');
    const kept = (normalizeClaims({ meta: { tags } }).meta as { tags: SecretTags }).tags;
    expect(kept).toBe(tags);
    expect(() => kept.toJSON()).not.toThrow();
    expect(kept.toJSON()).toBe('secret:2');
    const vc = await issuer.issueVC(HOLDER, { meta: { tags } }, {});
    const subject = signedVcOf(vc).credentialSubject as Record<string, unknown>;
    // エンジン差（継承 `toJSON` を呼ぶか否か）を吸収するため、元の値の直列化結果と比較する。
    expect(subject.meta).toEqual({ tags: JSON.parse(JSON.stringify(tags)) as unknown });
  });

  it('入れ子の非列挙 own プロパティの Art.9 属性は従来どおり 10607 で拒否する', async () => {
    // 深いコピーが非列挙フラグを落とすと、走査器がこのキーを見なくなる（ガードが狭まる）か、
    // 逆に列挙可能へ格上げして**今まで載らなかった値を署名済み VC に載せる**。どちらも退行。
    const nested: Record<string, unknown> = { type: 'DocumentVerification' };
    Object.defineProperty(nested, 'health', { value: 'HIV+', enumerable: false });
    const before = revocation.remaining;
    await expect(
      issuer.issueVC(HOLDER, { degree: 'BSc' }, { evidence: [nested] } as unknown as IssueOptions),
    ).rejects.toMatchObject({ code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE });
    expect(revocation.remaining).toBe(before);
  });

  it('入れ子の非列挙 own プロパティは署名済み VC に載らない（列挙可能へ格上げしない）', async () => {
    const nested: Record<string, unknown> = { type: 'DocumentVerification' };
    Object.defineProperty(nested, 'internalNote', { value: 'secret', enumerable: false });
    const vc = await issuer.issueVC(HOLDER, { degree: 'BSc' }, {
      evidence: [nested],
    } as unknown as IssueOptions);
    expect(signedVcOf(vc).evidence).toEqual([{ type: 'DocumentVerification' }]);
  });
});
