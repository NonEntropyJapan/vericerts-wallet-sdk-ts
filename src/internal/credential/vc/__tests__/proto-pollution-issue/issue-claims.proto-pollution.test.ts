/**
 * JWT-VC 発行の**登録クレーム**への汚染混入テスト。
 *
 * `issue.ts` の `buildSigningInput` は VC 本体を JWT-VC payload（`iss` / `sub` / `nbf` / `iat` /
 * `exp` / `jti`）へマッピングして**そのまま署名する**。ここをプロトタイプ鎖で読むと、当該
 * フィールドを**持たない** VC でも `Object.prototype` の汚染値が署名済み JWT に載る。
 *
 * 本関数は全発行経路（SubjectBinding・DelegationGrant・Issuer モジュール等）の共通基盤であり、
 * ここが鎖読みのままだと上流モジュールの own 化がそのまま無効化される。実際
 * `subject-binding.ts` の `vc.id` を own 化しても、外側 JWT の `jti` には
 * `Object.prototype.id` の汚染値が載り続けていた（受入条件「汚染値が署名済み VC のクレームに
 * 載らない」が `id` について未達だった）。
 *
 * 検証はすべて「そのプロパティを**省略した** VC / オプション」で行う（明示指定は汚染と無関係に
 * 通るため無価値）。`{ id: undefined }` はスプレッドで own キーを生やして汚染値が届かなくなる
 * ため、分割代入でキーごと落とす。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { issueCredential, issueCredentialAsync } from '../../issue.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const ISSUER_DID = 'did:example:issuer';
const SUBJECT_DID = 'did:example:subject';
const ISSUANCE_DATE = '2026-01-01T00:00:00Z';
const NOW_SECONDS = 1_767_225_600;

/** 攻撃者が仕込む汚染値。 */
const EVIL_ID = 'urn:uuid:evil-jti';
const EVIL_DID = 'did:example:attacker';
const EVIL_DATE = '2099-01-01T00:00:00Z';
const EVIL_SECONDS = 4_100_000_000;

/** 任意欄（`id` / `expirationDate`）を持たない最小 VC。 */
function baseVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IdentityCredential'],
    issuer: ISSUER_DID,
    credentialSubject: { id: SUBJECT_DID },
    issuanceDate: ISSUANCE_DATE,
  };
}

/** 型のない JS 呼び出し（プロパティ欠落）を再現するためのキャスト。 */
function omit<T>(value: unknown): T {
  return value as T;
}

/** 署名済み JWT の payload をデコードする。 */
function decodePayload(jwt: string): Record<string, unknown> {
  const [, payload = ''] = jwt.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('issueCredential の VC 本体読み取りの汚染耐性', () => {
  it('id を持たない VC は継承した id を jti に載せない', () => {
    // そのもの。鎖読みだと `Object.prototype.id` が署名済み JWT の `jti` になる。
    const jwt = withPollutedPrototype({ id: EVIL_ID }, () =>
      issueCredential(baseVc(), SIGNER, { nowSeconds: NOW_SECONDS }),
    );

    const payload = decodePayload(jwt);
    expect(payload.jti).toBeUndefined();
    // VC 本体（`vc` クレーム）にも汚染値が詰め直されていないこと。
    expect((payload.vc as Record<string, unknown>).id).toBeUndefined();
  });

  it('アクセサ汚染の id でも jti に載らない', () => {
    const jwt = withPollutedPrototypeAccessor({ id: () => EVIL_ID }, () =>
      issueCredential(baseVc(), SIGNER, { nowSeconds: NOW_SECONDS }),
    );

    expect(decodePayload(jwt).jti).toBeUndefined();
  });

  it('expirationDate を持たない（無期限）VC は継承した期限を exp に載せない', () => {
    const jwt = withPollutedPrototype({ expirationDate: EVIL_DATE }, () =>
      issueCredential(baseVc(), SIGNER, { nowSeconds: NOW_SECONDS }),
    );

    expect(decodePayload(jwt).exp).toBeUndefined();
  });

  it('issuer を持たない VC は継承した発行者で署名せず fail-closed に倒す（3002）', () => {
    // 汚染値を `iss` に載せないだけでなく、`iss` の無い JWT に**署名鍵を使わない**こと。
    // 検証側（`assertVerifiableCredential`）が必ず 3002 で弾くため、発行しても使えない。
    const { issuer: _omitted, ...withoutIssuer } = baseVc();
    expect(() =>
      withPollutedPrototype({ issuer: EVIL_DID }, () =>
        issueCredential(omit<VerifiableCredential>(withoutIssuer), SIGNER, {
          nowSeconds: NOW_SECONDS,
        }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
  });

  it('credentialSubject.id を持たない VC は継承した subject を sub に載せない', () => {
    const vc = { ...baseVc(), credentialSubject: { name: 'Alice' } };
    const jwt = withPollutedPrototype({ id: EVIL_DID }, () =>
      issueCredential(vc, SIGNER, { nowSeconds: NOW_SECONDS }),
    );

    const payload = decodePayload(jwt);
    expect(payload.sub).toBeUndefined();
    // 同じ汚染キーで `jti` も塞がれていること（`vc.id` と `credentialSubject.id` は同名）。
    expect(payload.jti).toBeUndefined();
  });

  it('credentialSubject を持たない VC は継承したクレーム本体を採用せず fail-closed に倒す（3002）', () => {
    const { credentialSubject: _omitted, ...withoutSubject } = baseVc();
    expect(() =>
      withPollutedPrototype({ credentialSubject: { id: EVIL_DID } }, () =>
        issueCredential(omit<VerifiableCredential>(withoutSubject), SIGNER, {
          nowSeconds: NOW_SECONDS,
        }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
  });

  it('credentialSubject が null の VC は生 TypeError にせず 3002 に正規化する', () => {
    // `ownProperty(null, 'id')` は `Object.hasOwn(null, …)` で生の `TypeError` を投げ、
    // `VericertsError` に正規化されないまま呼び出し側へ抜けていた。
    const vc = omit<VerifiableCredential>({ ...baseVc(), credentialSubject: null });
    expect(() => issueCredential(vc, SIGNER, { nowSeconds: NOW_SECONDS })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('issuanceDate を持たない VC は継承した時刻で nbf を作らず fail-closed に倒す（3002）', () => {
    const { issuanceDate: _omitted, ...withoutIssuance } = baseVc();
    expect(() =>
      withPollutedPrototype({ issuanceDate: EVIL_DATE }, () =>
        issueCredential(omit<VerifiableCredential>(withoutIssuance), SIGNER, {
          nowSeconds: NOW_SECONDS,
        }),
      ),
    ).toThrow(new VericertsError(ErrorCodes.VC_SCHEMA_INVALID));
  });
});

describe('issueCredential のオプション読み取りの汚染耐性', () => {
  it('nowSeconds を省略した発行は継承した時刻を iat に載せない', () => {
    // 既定引数 `{}` も `Object.prototype` を継承する。鎖読みだと省略しただけで `iat` が汚染される。
    const jwt = withPollutedPrototype({ nowSeconds: EVIL_SECONDS }, () =>
      issueCredential(baseVc(), SIGNER),
    );

    const payload = decodePayload(jwt);
    expect(payload.iat).not.toBe(EVIL_SECONDS);
    // 汚染を弾いた結果は実時刻へのフォールバック。
    expect(Math.abs((payload.iat as number) - Math.floor(Date.now() / 1000))).toBeLessThan(60);
  });

  it('非同期発行（issueCredentialAsync）でも同じ読み取り規律が効く', async () => {
    const jwt = await withPollutedPrototype({ id: EVIL_ID, nowSeconds: EVIL_SECONDS }, () =>
      issueCredentialAsync(baseVc(), SIGNER),
    );

    const payload = decodePayload(jwt);
    expect(payload.jti).toBeUndefined();
    expect(payload.iat).not.toBe(EVIL_SECONDS);
  });
});

describe('JWT-VC 発行の正常系（own 化しすぎの回帰検出）', () => {
  it('明示的に持つフィールドは従来どおり登録クレームに載る', () => {
    const vc: VerifiableCredential = {
      ...baseVc(),
      id: 'urn:uuid:real-vc',
      expirationDate: '2027-01-01T00:00:00Z',
    };
    const jwt = issueCredential(vc, SIGNER, { nowSeconds: NOW_SECONDS });

    const payload = decodePayload(jwt);
    expect(payload.iss).toBe(ISSUER_DID);
    expect(payload.sub).toBe(SUBJECT_DID);
    expect(payload.jti).toBe('urn:uuid:real-vc');
    expect(payload.iat).toBe(NOW_SECONDS);
    expect(payload.nbf).toBe(Math.floor(Date.parse(ISSUANCE_DATE) / 1000));
    expect(payload.exp).toBe(Math.floor(Date.parse('2027-01-01T00:00:00Z') / 1000));
  });

  it('非列挙の own プロパティで持つフィールドも登録クレームに載る', () => {
    // `ownProperty` は `Object.hasOwn` 判定なので列挙可否を問わない。スプレッド由来の
    // own 化しすぎ（列挙可能なキーだけ拾う実装）への退行を検出する。
    const vc = baseVc();
    Object.defineProperty(vc, 'id', { value: 'urn:uuid:hidden', enumerable: false });
    const jwt = issueCredential(vc, SIGNER, { nowSeconds: NOW_SECONDS });

    expect(decodePayload(jwt).jti).toBe('urn:uuid:hidden');
  });
});
