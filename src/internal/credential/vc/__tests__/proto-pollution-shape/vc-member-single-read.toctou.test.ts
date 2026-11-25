/**
 * VC の**検査済みメンバを読み直さない**こと（single-read）の回帰テスト。
 * VP 側 `assertVerifiablePresentationMembers` の兄弟。
 *
 * 是正前の形: `verify.ts` の `assertEnvelopeBinding` は `assertVerifiableCredential` で構造検証を
 * 済ませた**後で** `vc.issuer` / `vc.credentialSubject` / `vc.issuanceDate` / `vc.expirationDate` を
 * 鎖読みで読み直していた。own アクセサ付きの VC を渡されると 2 度目の読みが別の値を返し得るため、
 * **構造検証が見た値と envelope↔body 突合に使う値が食い違う**（TOCTOU）。VP 側は
 * `assertVerifiablePresentationMembers` の戻り値をそのまま下流へ流す形で同じ穴を塞いであり、
 * VC 側にだけ re-read が残って対称性が崩れていた。
 *
 * 是正は VP 側と同じ形: `assertVerifiableCredentialMembers` が**検査に使った own 値**を
 * `AssertedVerifiableCredential` として返し、`assertEnvelopeBinding` はその戻り値だけを使う。
 *
 * 検証内容:
 * 1. 読むたびに別の値を返す own アクセサを植えた VC でも、返る検査済みメンバは**第 1 読み
 *    （＝実際に検証した値）**であり、各メンバの読みは 1 回に限られる。
 * 2. `assertEnvelopeBinding` が VC 本体を読み直していないことを**構造的に**固定する
 *    （JWT payload はパース境界で素の data プロパティになるためアクセサを注入できず、
 *    公開 API 経由では再読みを観測できない。`trust/federation` の fail-open 非配線検査と同じ手法）。
 */

import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
  assertVerifiableCredential,
  assertVerifiableCredentialMembers,
} from '../../../presentation/vc-assert.js';
import { VC_TYPE, VC_V2_CONTEXT } from '../../../presentation/vp.js';

/** 構造検証が実際に見る値（第 1 読み）。 */
const CHECKED = {
  issuer: 'did:example:checked-issuer',
  issuanceDate: '2025-12-01T00:00:00Z',
  expirationDate: '2026-12-01T00:00:00Z',
  credentialSubject: { id: 'did:example:checked-subject' },
} as const;

/** 読み直したときにすり替わる値（第 2 読み以降）。 */
const SWAPPED = {
  issuer: 'did:example:swapped-issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  expirationDate: '2030-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:swapped-subject' },
} as const;

/** 読むたびに別の値を返す own アクセサを持つ VC と、メンバごとの読み取り回数。 */
interface ToctouFixture {
  /** 検証対象の VC（own アクセサ付き）。 */
  readonly vc: Record<string, unknown>;
  /** メンバ名 → これまでの読み取り回数。 */
  readonly reads: ReadonlyMap<string, number>;
}

/**
 * TOCTOU 再現用の VC を組む。
 *
 * `@context` / `type` は素の data プロパティ、突合に使われる 4 メンバは
 * 「1 回目は {@link CHECKED}、2 回目以降は {@link SWAPPED}」を返す own アクセサにする。
 *
 * @returns VC 本体と読み取り回数カウンタ。
 */
function toctouFixture(): ToctouFixture {
  const reads = new Map<string, number>();
  const vc: Record<string, unknown> = { '@context': [VC_V2_CONTEXT], type: [VC_TYPE] };
  const swapping = (key: string, first: unknown, second: unknown): void => {
    reads.set(key, 0);
    Object.defineProperty(vc, key, {
      configurable: true,
      enumerable: true,
      get: (): unknown => {
        const seen = (reads.get(key) ?? 0) + 1;
        reads.set(key, seen);
        return seen === 1 ? first : second;
      },
    });
  };
  swapping('issuer', CHECKED.issuer, SWAPPED.issuer);
  swapping('issuanceDate', CHECKED.issuanceDate, SWAPPED.issuanceDate);
  swapping('expirationDate', CHECKED.expirationDate, SWAPPED.expirationDate);
  swapping('credentialSubject', CHECKED.credentialSubject, SWAPPED.credentialSubject);
  return { vc, reads };
}

describe('assertVerifiableCredentialMembers は検査に使った own 値を返す', () => {
  it('返るメンバは第 1 読み（検証した値）で、読み直し後の値ではない', () => {
    const { vc } = toctouFixture();

    const asserted = assertVerifiableCredentialMembers(vc);

    expect(asserted.issuer).toBe(CHECKED.issuer);
    expect(asserted.issuanceDate).toBe(CHECKED.issuanceDate);
    expect(asserted.expirationDate).toBe(CHECKED.expirationDate);
    expect(asserted.credentialSubject).toBe(CHECKED.credentialSubject);
  });

  it('各メンバの読みは 1 回だけ（構造検証と下流で読みを共有する）', () => {
    const { vc, reads } = toctouFixture();

    assertVerifiableCredentialMembers(vc);

    expect(reads.get('issuer')).toBe(1);
    expect(reads.get('issuanceDate')).toBe(1);
    expect(reads.get('expirationDate')).toBe(1);
    expect(reads.get('credentialSubject')).toBe(1);
  });

  it('VC 本体は同一参照で返る（コピーしない）', () => {
    const { vc } = toctouFixture();

    expect(assertVerifiableCredentialMembers(vc).vc as unknown).toBe(vc);
    // 兄弟の公開 API も従来どおり同一参照を返す（形は変えていない）。
    expect(assertVerifiableCredential(toctouFixture().vc)).toBeDefined();
  });

  it('対照: フィクスチャは実際に読み直しで別値を返す（TOCTOU が成立する形である）', () => {
    const { vc } = toctouFixture();

    const asserted = assertVerifiableCredentialMembers(vc);

    expect(vc.issuer).toBe(SWAPPED.issuer);
    expect(vc.issuer).not.toBe(asserted.issuer);
    expect(vc.credentialSubject).not.toBe(asserted.credentialSubject);
  });
});

describe('assertEnvelopeBinding は VC 本体を読み直さない（構造検査）', () => {
  /** `credential/vc/verify.ts` のソース。 */
  const source = readFileSync(new URL('../../verify.ts', import.meta.url), 'utf8');

  /** 表現（`vc` ラップ / VC 2.0 系 flat）ごとの検査済みメンバ取得。 */
  const members = readFileSync(new URL('../../jwt-vc-members.ts', import.meta.url), 'utf8');

  it('検査済みメンバを返す API を使う（verify.ts は本体を自分で読まず jwtVcBodyMembersOf に任せる）', () => {
    expect(source).toContain('jwtVcBodyMembersOf(');
    expect(members).toContain('assertVerifiableCredentialMembers(');
    expect(members).toContain('assertVerifiableCredentialV2Members(');
  });

  it('jwt-vc-members.ts も検査済みメンバを読み直さない（flat 側を含む）', () => {
    expect(members).not.toMatch(/ownProperty<[^>]*>\(body,/);
    expect(members).not.toMatch(/ownProperty<[^>]*>\(checked\.vc,/);
    expect(members).not.toMatch(/\bvc\.(issuer|credentialSubject|issuanceDate|validFrom)\b/);
  });
  it('是正前の鎖読み（構造検証の後で VC 本体を読み直す形）が復活していない', () => {
    // JSDoc / コメント中の `vc.issuer` などの言及は許容し、**コードとしての形**だけを禁止する。
    expect(source).not.toMatch(/if \(iss !== vc\.issuer\)/);
    expect(source).not.toMatch(/nbf !== isoToNumericDate\(vc\./);
    expect(source).not.toMatch(/ownProperty<unknown>\(vc\.credentialSubject,/);
    expect(source).not.toMatch(/ownProperty<string>\(vc, 'expirationDate'\)/);
  });
});
