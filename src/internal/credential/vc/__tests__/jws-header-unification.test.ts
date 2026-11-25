/**
 * JWS ヘッダ組み立ての `buildJwsHeader` 一本化を横断的に固定する回帰テスト。
 *
 * `signer.kid` がヘッダに反映されるよう、
 * JWT-VP 発行 / WUA PoP / 署名付き Dashboard ログ / Status List Token 発行 / Pseudonym Attestation・
 * SIOP `id_token` を `buildJwsHeader` へ寄せた。本テストは以下を経路横断で固定する:
 *
 * - `signer.kid` 設定時、ヘッダのキー順が `alg` → `kid` → `typ` である。
 * - `signer.kid` 未設定時、ヘッダが従来どおり `{"alg":...,"typ":...}` と完全一致する（後方互換）。
 * - `Object.prototype.kid` が汚染されていても、`kid` を持たない signer のヘッダに混入しない。
 *
 * Pseudonym Attestation / SIOP `id_token` の 2 経路は signer を引数に取らず、派生した Pseudonym
 * 秘密鍵から内部で `createPrivateKeySigner` を組み立てる。`signer.kid` を外から設定する術がないため
 * `kid` 付きの変種は存在せず、`kid` なしのヘッダ完全一致だけを別 `describe` で固定する。
 *
 * DPoP Proof（`typ` → `alg` → `jwk`）と OID4VCI Proof JWT（`typ` → `alg` → `kid`、値は
 * `options.keyId` 由来）はキー順・`kid` の出所が異なるため対象外。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { issuePseudonymAttestation } from '../../../eudi/pseudonym/attestation.js';
import { presentPseudonym } from '../../../eudi/pseudonym/siop.js';
import {
  makeWuaJwt,
  toP256Jwk,
  WSCD_PRIVATE_KEY,
} from '../../../eudi/wua/__tests__/wua-fixtures.js';
import { buildWuaProofOfPossession } from '../../../eudi/wua/proof.js';
import { parseWalletUnitAttestation } from '../../../eudi/wua/wua.js';
import { DashboardLog } from '../../../gdpr/dashboard-log/dashboard-log.js';
import { signStatusListToken } from '../../../issuer/status-list-token.js';
import { sampleVp } from '../../presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../presentation/issue.js';
import { buildJwsHeader, type CredentialSigner, createPrivateKeySigner } from '../signer.js';

/** テスト用秘密鍵（本テストは header のバイト列だけを見るため鍵の中身は任意）。 */
const KEY = new Uint8Array(32).fill(53);
const KID = 'did:example:issuer#key-1';

/** signer を `kid` 付き / なしで用意する。 */
function signer(kid?: string): CredentialSigner {
  const base = createPrivateKeySigner(KEY, 'ES256');
  return kid === undefined ? base : { ...base, kid };
}

/** コンパクト JWS のヘッダ部を UTF-8 文字列（＝キー順を保持した生 JSON）へ戻す。 */
function headerJson(jws: string): string {
  return Buffer.from(jws.split('.')[0] ?? '', 'base64url').toString('utf8');
}

/** 経路名 → `kid` 付き / なしのコンパクト JWS を作る関数。 */
interface JwsPathCase {
  /** 経路の表示名（`WUA PoP` は cnf.jwk バインドのため署名鍵が異なる）。 */
  readonly name: string;
  /** その経路が出力する JWS ヘッダの `typ`。 */
  readonly typ: string;
  /** 与えた signer でコンパクト JWS を 1 本作る。 */
  readonly sign: (s: CredentialSigner) => Promise<string> | string;
}

const PATHS: JwsPathCase[] = [
  {
    name: 'JWT-VP 発行（issuePresentation）',
    typ: 'JWT',
    sign: (s) => issuePresentation(sampleVp(), s),
  },
  {
    name: 'Status List Token 発行（signStatusListToken）',
    typ: 'statuslist+jwt',
    sign: (s) =>
      signStatusListToken(
        { issuer: 'did:example:issuer', uri: 'https://issuer.example/s/1', bits: 1, lst: 'eNo' },
        s,
        { iatSeconds: 1_767_225_600 },
      ),
  },
  {
    name: 'WUA PoP（buildWuaProofOfPossession）',
    typ: 'wuapop+jwt',
    sign: (s) =>
      buildWuaProofOfPossession(
        parseWalletUnitAttestation(
          makeWuaJwt(WSCD_PRIVATE_KEY, {}, { cnfJwk: toP256Jwk(WSCD_PRIVATE_KEY) }),
        ),
        {
          aud: 'https://issuer.example',
          nonce: 'n-1',
          jti: '3b241101-e2bb-4255-8caf-4136c566a962',
        },
        // WUA PoP は cnf.jwk にバインドされた鍵でのみ署名できるため WSCD 鍵を使う。
        s,
        1_712_345_700,
      ),
  },
  {
    name: '署名付き Dashboard ログ（DashboardLog.append）',
    typ: 'JWT',
    sign: async (s) => {
      const log = new DashboardLog(new MemoryStorage(), () => new Date('2026-07-02T00:00:00.000Z'));
      const entry = await log.append('correctionRequest', { vcId: 'vc-1' }, s);
      return entry.signature;
    },
  },
];

/** WUA PoP だけは cnf.jwk バインド検査があるため WSCD 鍵から signer を作る。 */
function signerForPath(name: string, kid?: string): CredentialSigner {
  if (!name.startsWith('WUA PoP')) {
    return signer(kid);
  }
  const base = createPrivateKeySigner(WSCD_PRIVATE_KEY, 'ES256');
  return kid === undefined ? base : { ...base, kid };
}

describe.each(PATHS)('JWS ヘッダ一本化: $name', ({ name, typ, sign }) => {
  it('kid 未設定なら従来どおり {"alg","typ"} と完全一致する（後方互換）', async () => {
    const jws = await sign(signerForPath(name));
    expect(headerJson(jws)).toBe(`{"alg":"ES256","typ":"${typ}"}`);
  });

  it('kid 設定時は alg → kid → typ の順で出力する', async () => {
    const jws = await sign(signerForPath(name, KID));
    expect(headerJson(jws)).toBe(`{"alg":"ES256","kid":"${KID}","typ":"${typ}"}`);
  });
});

/** Pseudonym 鍵派生のマスター種（本テストは header のバイト列だけを見るため値は任意）。 */
const MASTER_SEED = new Uint8Array(32).fill(71);

describe('JWS ヘッダ一本化: signer を内部生成する経路（kid 変種なし）', () => {
  it('Pseudonym Attestation は {"alg","typ":"pseudonym+jwt"} と完全一致する', () => {
    const { jwt } = issuePseudonymAttestation('https://rp.example', MASTER_SEED, {
      issuer: 'urn:wallet:instance:1',
      nowSeconds: 1_767_225_600,
    });
    expect(headerJson(jwt)).toBe('{"alg":"ES256","typ":"pseudonym+jwt"}');
  });

  it('SIOP id_token は {"alg","typ":"JWT"} と完全一致する', () => {
    const { idToken } = presentPseudonym(
      { clientId: 'https://rp.example', nonce: 'n-1' },
      'https://rp.example',
      MASTER_SEED,
      { nowSeconds: 1_767_225_600 },
    );
    expect(headerJson(idToken)).toBe('{"alg":"ES256","typ":"JWT"}');
  });
});

describe('buildJwsHeader: Object.prototype 汚染からの防御', () => {
  /** 汚染を必ず戻したうえで本体を実行する。 */
  function withPollutedKid<T>(value: string, body: () => T): T {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted.kid = value;
    try {
      return body();
    } finally {
      delete polluted.kid;
    }
  }

  it('継承した kid はヘッダに載らない', () => {
    // `source.kid !== undefined` はプロトタイプ鎖を辿るため、汚染値がヘッダへ載っていた。
    const header = withPollutedKid('did:web:attacker.example#key-1', () =>
      buildJwsHeader({ alg: 'ES256' }, 'JWT'),
    );
    expect(JSON.stringify(header)).toBe('{"alg":"ES256","typ":"JWT"}');
  });

  it('自身の kid は従来どおり alg → kid → typ の順で載る', () => {
    // 汚染下でも「自身の kid」は正しく採用される（過剰な拒否をしない）。
    const header = withPollutedKid('did:web:attacker.example#key-1', () =>
      buildJwsHeader({ alg: 'ES256', kid: KID }, 'JWT'),
    );
    expect(JSON.stringify(header)).toBe(`{"alg":"ES256","kid":"${KID}","typ":"JWT"}`);
  });

  it('汚染下でも発行 API（JWT-VP）のヘッダへ攻撃者の kid が混入しない', async () => {
    const jws = await withPollutedKid('did:web:attacker.example#key-1', async () =>
      issuePresentation(sampleVp(), signer()),
    );
    expect(headerJson(jws)).toBe('{"alg":"ES256","typ":"JWT"}');
  });
});
