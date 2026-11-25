/**
 * SD-JWT VC 発行プリミティブ（`createSdJwt` / `createSdJwtAsync`）の GDPR Art.9 ガード回帰テスト
 * （エラー `10607`）。
 *
 * SD-JWT の発行経路は JWT-VC の署名プリミティブ（`vc/issue.ts`）を通らないため、`sdjwt/gdpr-guard.ts`
 * が同等の関門を担う。ここで固定するのは JWT-VC 側と同じ不変条件
 * **「発行された SD-JWT（平文 payload と同梱 Disclosure の双方）に Art.9 属性は載らない」**である。
 *
 * SD-JWT 固有の核心は **`disclosureClaims` に指定された禁止属性**である。開示クレームは Disclosure
 * 側へ回り、payload には `_sd` の digest しか残らないため、payload だけを走査するガードでは
 * 「まさに隠したい Art.9 属性」を取り逃す。平文クレームのケースとは別のテストとして明示する。
 *
 * 検証内容:
 * - 平文クレーム / 開示クレームのどちらに置いた禁止属性も `10607` で拒否する（同期版・非同期版）。
 *   入れ子・配列要素・命名揺れ（`birthDate` / `birth_date` / 圧縮 IRI / 展開済み IRI）を覆う。
 * - 拒否時に `signer.sign` が **1 度も呼ばれない**（署名鍵を使う前に fail-closed）。例外に
 *   属性名・クレーム値を載せない（PII 非開示）。
 * - `NON_DISCLOSABLE_CLAIMS` により平文 payload に残されるクレーム経由の禁止属性も拒否する。
 * - `cnf` / `status` は payload に載るので覆われ、`salts`（payload にも Disclosure にも載らない）は
 *   走査対象外である — 実装の実挙動そのままを固定する。
 * - `claims` に存在しない `disclosureClaims: ['health']` 単独では拒否しない（何も送出されない）。
 * - 無害なクレームは従来どおり発行でき、検証で復元できる（過剰検知の回帰防止）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../vc/signer.js';
import {
  type ConfirmationClaim,
  type CreateSdJwtOptions,
  createSdJwt,
  createSdJwtAsync,
  parseSdJwt,
} from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(23);
const HOLDER_KEY = new Uint8Array(32).fill(29);
const VCT = 'https://example.com/credentials/identity';
const ISSUER_DID = 'did:example:issuer';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const CNF: ConfirmationClaim = { jwk: HOLDER_JWK };

/** `sign` の呼び出し回数を数える signer（fail-closed の確認用）。 */
interface CountingSigner {
  /** 委譲先の実 signer と同一の署名を返す signer。 */
  readonly signer: CredentialSigner;
  /** `sign` が呼ばれた回数。 */
  readonly calls: () => number;
}

/** 署名回数を数える signer を作る（ガードが署名鍵に触れる前に倒れることの直接観測用）。 */
function countingSigner(): CountingSigner {
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

/** 平文クレームに違反を置いた発行オプション（`disclosureClaims` は空 = すべて payload に載る）。 */
const VIOLATING_PLAIN_CLAIMS: readonly [string, Readonly<Record<string, unknown>>][] = [
  ['トップレベルの health', { health: 'HIV+' }],
  ['トップレベルの religion', { religion: 'x' }],
  ['入れ子の profile.diagnosis', { profile: { diagnosis: 'x' } }],
  ['配列要素の documents[0].national_id', { documents: [{ national_id: 'x' }] }],
  ['camelCase の birthDate', { birthDate: '1990-01-01' }],
  ['snake_case の birth_date', { birth_date: '1990-01-01' }],
  ['圧縮 IRI の pid:birth_date', { 'pid:birth_date': '1990-01-01' }],
  [
    '展開済み IRI の https://schema.org/birthDate',
    { 'https://schema.org/birthDate': '1990-01-01' },
  ],
];

/**
 * 開示クレームに違反を置いた発行オプション（payload には `_sd` の digest しか残らない）。
 *
 * `claimName` が禁止語彙そのもののケースと、開示する**値の中**に禁止属性が入れ子で潜むケースの
 * 両方を含める。前者は Disclosure の `[salt, claimName, value]` 配列の「値の位置」に属性名が
 * 来るため、エンコード済み文字列をそのまま走査しても検知できない（デコードが要る）。
 */
const VIOLATING_DISCLOSURE_CLAIMS: readonly [string, readonly string[], Record<string, unknown>][] =
  [
    ['開示クレーム名が health', ['health'], { health: 'HIV+' }],
    ['開示クレーム名が birth_date', ['birth_date'], { birth_date: '1990-01-01' }],
    [
      '開示クレームの値に入れ子の diagnosis',
      ['medical'],
      { medical: { record: { diagnosis: 'x' } } },
    ],
    ['開示クレームの値の配列要素に ssn', ['docs'], { docs: [{ ssn: '000-00-0000' }] }],
  ];

describe('createSdJwt / createSdJwtAsync の Art.9 ガード: 平文クレーム', () => {
  for (const [label, claims] of VIOLATING_PLAIN_CLAIMS) {
    it(`${label} を含む平文クレームの同期発行を 10607 で拒否する`, () => {
      const { signer, calls } = countingSigner();
      expectIssuanceRejected(() => createSdJwt(signer, { vct: VCT, disclosureClaims: [], claims }));
      expect(calls()).toBe(0);
    });

    // 非同期版は独立した関数であり、`buildSdJwtIssuanceParts` の共有が外れると片方が無ガードになる。
    it(`${label} を含む平文クレームの非同期発行を 10607 で拒否する`, async () => {
      const { signer, calls } = countingSigner();
      const promise = createSdJwtAsync(signer, { vct: VCT, disclosureClaims: [], claims });
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
      expect(calls()).toBe(0);
    });
  }
});

describe('createSdJwt の Art.9 ガード: 開示クレーム（SD-JWT 固有）', () => {
  // 本ファイルの核心。開示クレームは payload から消えるため、payload だけを走査するガードは
  // 「Art.9 属性を選択的開示で隠した発行」をそのまま通してしまう。
  for (const [label, disclosureClaims, claims] of VIOLATING_DISCLOSURE_CLAIMS) {
    it(`${label} の同期発行を 10607 で拒否する`, () => {
      const { signer, calls } = countingSigner();
      expectIssuanceRejected(() => createSdJwt(signer, { vct: VCT, disclosureClaims, claims }));
      expect(calls()).toBe(0);
    });

    it(`${label} の非同期発行を 10607 で拒否する`, async () => {
      const { signer, calls } = countingSigner();
      const promise = createSdJwtAsync(signer, { vct: VCT, disclosureClaims, claims });
      await expect(promise).rejects.toMatchObject({
        code: ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE,
      });
      expect(calls()).toBe(0);
    });
  }

  it('禁止属性が payload から消えていること自体を確認する（走査対象が Disclosure であること）', () => {
    // 対照実験。同じ形の無害なクレームを開示すると payload には `_sd` の digest しか残らない。
    // つまり上のケース群は payload 走査では検知できず、Disclosure のデコードが必須である。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['nickname'],
      claims: { nickname: 'Al' },
    });
    const { issuerJwt, disclosures } = parseSdJwt(sdJwt);
    const [, payloadSeg = ''] = issuerJwt.split('.');
    const payload = JSON.parse(Buffer.from(payloadSeg, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(payload, 'nickname')).toBe(false);
    expect((payload._sd as readonly string[]).length).toBe(1);
    expect(disclosures[0]?.claimName).toBe('nickname');
  });
});

describe('createSdJwt の Art.9 ガード: 走査範囲', () => {
  it('NON_DISCLOSABLE_CLAIMS で平文 payload に残る cnf 経由の禁止属性も 10607 で拒否する', () => {
    // `cnf` は `disclosureClaims` に挙げても Disclosure へは回らず平文 payload に残る
    // （`NON_DISCLOSABLE_CLAIMS`）。「開示指定したから Disclosure 側だけ見ればよい」という
    // 実装になっていると、この経路が両方の走査から漏れる。
    const { signer, calls } = countingSigner();
    expectIssuanceRejected(() =>
      createSdJwt(signer, {
        vct: VCT,
        disclosureClaims: ['cnf'],
        claims: { cnf: { jwk: HOLDER_JWK, health: 'HIV+' }, degree: 'BSc' },
      }),
    );
    expect(calls()).toBe(0);
  });

  it('opts.cnf 由来の禁止属性も 10607 で拒否する（payload に載るため走査対象）', () => {
    // `ConfirmationClaim` は追加プロパティを宣言していないが、TypeScript の余剰プロパティ検査は
    // 新鮮なオブジェクトリテラルにしか働かない。変数経由なら型検査を素通りして payload へ載る。
    const cnf = { jwk: HOLDER_JWK, religion: 'x' } as ConfirmationClaim;
    const opts = { vct: VCT, cnf, disclosureClaims: [], claims: { degree: 'BSc' } };
    expectIssuanceRejected(() => createSdJwt(ISSUER_SIGNER, opts));
  });

  it('opts.status 由来の禁止属性も 10607 で拒否する（payload に載るため走査対象）', () => {
    const status = {
      status_list: { idx: 0, uri: 'https://issuer.example/status/1' },
      diagnosis: 'x',
    } as CreateSdJwtOptions['status'];
    const opts = { vct: VCT, status, disclosureClaims: [], claims: { degree: 'BSc' } };
    expectIssuanceRejected(() => createSdJwt(ISSUER_SIGNER, opts));
  });

  it('opts.salts のキーは走査対象外（payload にも Disclosure にも載らないため）', () => {
    // 実装が走査するのは「送出される表現」= payload と Disclosure だけである。`salts` は
    // salt を引くための対応表に過ぎず、対応するクレームが `claims` に無ければ何も送出されない。
    // ここで拒否してしまうと、送出されない値を理由に正当な発行が止まる（過剰検知）。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['degree'],
      claims: { degree: 'BSc' },
      salts: { health: 'unused-salt', degree: 'salt-degree' },
    });
    const { disclosures } = parseSdJwt(sdJwt);
    expect(disclosures.map((d) => d.claimName)).toEqual(['degree']);
  });

  it('claims に存在しない disclosureClaims: [health] 単独では拒否しない', () => {
    // `createSdJwt` は `claims` に無い開示クレーム名を単に無視する（Disclosure も `_sd` にも
    // 反映しない）。何も送出されない以上、禁止語彙が「指定された」だけで発行を止める理由はない。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['health'],
      claims: { degree: 'BSc' },
    });
    expect(parseSdJwt(sdJwt).disclosures).toEqual([]);
  });

  it('例外に属性名・クレーム値を載せない（PII 非開示）', () => {
    try {
      createSdJwt(ISSUER_SIGNER, {
        vct: VCT,
        disclosureClaims: ['religion'],
        claims: { religion: 'secret-value' },
      });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      const serialized = JSON.stringify({
        message: (error as VericertsError).message,
        context: (error as VericertsError).context,
      });
      expect(serialized).not.toContain('secret-value');
      expect(serialized).not.toContain('religion');
      // 発行はチェーンに書き込まないため `_ON_CHAIN`（10601）ではなく発行用の 10607。
      expect((error as VericertsError).code).toBe(ErrorCodes.GDPR_SPECIAL_CATEGORY_ISSUANCE);
    }
  });
});

describe('createSdJwt の Art.9 ガードの過剰検知防止', () => {
  // 陽性対照。これが無いと「疑わしきは拒否」方向へガードを厳しくしすぎる変更を検知できない。
  it('無害なクレームは発行でき、検証で開示クレームを復元できる', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: ISSUER_DID,
      cnf: CNF,
      disclosureClaims: ['nickname', 'age_over_18'],
      claims: { nickname: 'Al', age_over_18: true, role: 'admin' },
    });

    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, expectedVct: VCT });
    expect(result.claims.nickname).toBe('Al');
    expect(result.claims.age_over_18).toBe(true);
    expect(result.claims.role).toBe('admin');
    expect(result.cnf?.jwk.x).toBe(HOLDER_JWK.x);
  });

  it('Art.9 語彙に似た無害なクレーム名（healthy / raceTrack）は拒否しない', () => {
    // 判定は正規化名の**完全一致**であり部分一致ではない（`special-category.ts`）。
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      issuer: ISSUER_DID,
      disclosureClaims: ['healthy'],
      claims: { healthy: true, raceTrack: 'Suzuka' },
    });

    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, expectedVct: VCT });
    expect(result.claims.healthy).toBe(true);
    expect(result.claims.raceTrack).toBe('Suzuka');
  });
});
