/**
 * Bitstring Status List の生成（`signBitstringStatusListCredential` / `createBitstringStatusListEntry`）と
 * 検証（`resolveBitstringStatus` / `checkBitstringStatus`）の往復テスト（実署名・モック無し）。
 *
 * 検証内容:
 * - 発行 → 取得 → 検証 → 評価が revocation / suspension / message で成立する（statusSize / statusMessage 含む）。
 * - 署名不正・別鍵（3010）、`vc.id` ≠ 参照 URL（3010）、期限切れ（3024）、種別違い・最小長未満・
 *   不正な `encodedList`（3002）、エントリ不整合（種別 / 用途 / statusSize / index、3002）の拒否。
 * - 取得失敗は握りつぶさずそのまま伝播する（fail-closed）。
 */

import { describe, expect, it } from 'bun:test';
import { gzipSync } from 'node:zlib';
import { base64urlnopad } from '@scure/base';
import { issueCredential } from '../../../credential/vc/issue.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, type VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import {
  BitstringStatusList,
  createBitstringStatusListEntry,
  resolveBitstringStatus,
  signBitstringStatusListCredential,
  verifyBitstringStatusListCredential,
} from '../index.js';

const URL1 = 'https://issuer.example/status/1';
const ISSUER = 'did:web:issuer.example';
const IAT = 1_767_224_600;
const NOW = IAT + 100;

const KEY = new Uint8Array(32).fill(9);
const SIGNER = createPrivateKeySigner(KEY, 'ES256');
const pub = getP256PublicKey(KEY, false);
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const ISSUER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(pub.subarray(1, 33)),
  y: b64u(pub.subarray(33, 65)),
};
const OTHER_KEY = new Uint8Array(32).fill(10);
const OTHER_PUB = getP256PublicKey(OTHER_KEY, false);
const OTHER_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: b64u(OTHER_PUB.subarray(1, 33)),
  y: b64u(OTHER_PUB.subarray(33, 65)),
};

const verifyWith = (key: PublicKeyJwk = ISSUER_JWK, nowSeconds = NOW) => ({
  key: { publicKeyJwk: key },
  nowSeconds,
});

async function publish(
  list: BitstringStatusList,
  opts: { ttlSeconds?: number } = {},
): Promise<string> {
  return signBitstringStatusListCredential(list, SIGNER, {
    id: URL1,
    issuer: ISSUER,
    issuanceSeconds: IAT,
    ...opts,
  });
}

function resolveFrom(jwt: string, entry: unknown, nowSeconds = NOW, key = ISSUER_JWK) {
  return resolveBitstringStatus(entry, {
    fetchCredential: async () => jwt,
    verify: verifyWith(key, nowSeconds),
  });
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    return (e as VericertsError).code;
  }
  return 'no error';
}

function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('expected throw');
}

describe('生成 → 検証の往復', () => {
  it('revocation: 失効させたインデックスだけが revoked、他は valid', async () => {
    const list = BitstringStatusList.create('revocation', 1, 131_072);
    list.set(5, 1);
    const jwt = await publish(list);

    const revoked = await resolveFrom(jwt, createBitstringStatusListEntry(list, 5, URL1));
    const valid = await resolveFrom(jwt, createBitstringStatusListEntry(list, 6, URL1));

    expect(revoked).toEqual({ valid: false, purpose: 'revocation', value: 1 });
    expect(valid).toEqual({ valid: true, purpose: 'revocation', value: 0 });
  });

  it('suspension: 停止させたインデックスは valid=false、purpose は suspension', async () => {
    const list = BitstringStatusList.create('suspension', 1, 131_072);
    list.set(131_071, 1);
    const jwt = await publish(list);

    const result = await resolveFrom(jwt, createBitstringStatusListEntry(list, 131_071, URL1));

    expect(result).toEqual({ valid: false, purpose: 'suspension', value: 1 });
  });

  it('message: statusSize=2 の値と statusMessage の一致するメッセージを返す', async () => {
    const list = BitstringStatusList.create('message', 2, 65_536);
    list.set(7, 2);
    const jwt = await publish(list);
    const messages = [
      { status: '0x0', message: 'ok' },
      { status: '0x1', message: 'pending' },
      { status: '0x2', message: 'hold' },
    ];

    const hold = await resolveFrom(
      jwt,
      createBitstringStatusListEntry(list, 7, URL1, { statusMessage: messages }),
    );
    const ok = await resolveFrom(
      jwt,
      createBitstringStatusListEntry(list, 8, URL1, { statusMessage: messages }),
    );
    const unmatched = await resolveFrom(jwt, createBitstringStatusListEntry(list, 7, URL1));

    expect(hold).toEqual({ valid: false, purpose: 'message', value: 2, message: 'hold' });
    expect(ok).toEqual({ valid: true, purpose: 'message', value: 0, message: 'ok' });
    expect(unmatched).toEqual({ valid: false, purpose: 'message', value: 2 });
  });

  it('entry は statusSize を 1 のとき省略し、2 以上のとき載せる', () => {
    const one = BitstringStatusList.create('revocation', 1, 131_072);
    const two = BitstringStatusList.create('message', 2, 65_536);

    const e1 = createBitstringStatusListEntry(one, 3, URL1, { id: 'urn:uuid:1' });
    const e2 = createBitstringStatusListEntry(two, 3, URL1);

    expect(e1).toEqual({
      id: 'urn:uuid:1',
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '3',
      statusListCredential: URL1,
    });
    expect(e2.statusSize).toBe(2);
  });

  it('createBitstringStatusListEntry は範囲外 index・空 URL・非 message の statusMessage を 3002 で拒否する', () => {
    const list = BitstringStatusList.create('revocation', 1, 131_072);
    expectCode(
      () => createBitstringStatusListEntry(list, 131_072, URL1),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    expectCode(() => createBitstringStatusListEntry(list, 0, ''), ErrorCodes.VC_SCHEMA_INVALID);
    expectCode(
      () => createBitstringStatusListEntry(list, 0, URL1, { statusMessage: [] }),
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('リスト VC は ttlSeconds で exp を持ち、期限切れ後は 3024 で拒否される', async () => {
    const list = BitstringStatusList.create('revocation', 1, 131_072);
    const jwt = await publish(list, { ttlSeconds: 500 });
    const entry = createBitstringStatusListEntry(list, 1, URL1);

    // 既定のクロックスキュー（120 秒）を超えて期限を過ぎた時点で拒否される。
    expect(await codeOf(resolveFrom(jwt, entry, IAT + 499))).toBe('no error');
    expect(await codeOf(resolveFrom(jwt, entry, IAT + 500 + 121))).toBe(ErrorCodes.VC_EXPIRED);
  });

  it('signBitstringStatusListCredential は id / issuer 空・不正な ttlSeconds を 3002 で拒否する', async () => {
    const list = BitstringStatusList.create('revocation', 1, 131_072);
    for (const bad of [
      { id: '', issuer: ISSUER },
      { id: URL1, issuer: '' },
      { id: URL1, issuer: ISSUER, ttlSeconds: 0 },
      { id: URL1, issuer: ISSUER, ttlSeconds: 1.5 },
      { id: URL1, issuer: ISSUER, issuanceSeconds: -1 },
    ]) {
      expect(await codeOf(signBitstringStatusListCredential(list, SIGNER, bad))).toBe(
        ErrorCodes.VC_SCHEMA_INVALID,
      );
    }
  });
});

describe('リスト VC の検証失敗', () => {
  const list = BitstringStatusList.create('revocation', 1, 131_072);
  const entry = createBitstringStatusListEntry(list, 5, URL1);

  it('署名が改ざんされたリスト VC は 3010', async () => {
    const jwt = await publish(list);
    const [h, p, s] = jwt.split('.');
    const tampered = `${h}.${p}.${s?.slice(0, -2)}${s?.endsWith('AA') ? 'BB' : 'AA'}`;

    expect(await codeOf(resolveFrom(tampered, entry))).toBe(ErrorCodes.SIG_INVALID);
  });

  it('別の鍵の公開鍵で検証すると 3010', async () => {
    const jwt = await publish(list);

    expect(await codeOf(resolveFrom(jwt, entry, NOW, OTHER_JWK))).toBe(ErrorCodes.SIG_INVALID);
  });

  it('署名が有効でも vc.id が参照 URL と違うリスト（差し替え）は 3010', async () => {
    const jwt = await publish(list);
    const other = createBitstringStatusListEntry(list, 5, 'https://issuer.example/status/2');

    expect(await codeOf(resolveFrom(jwt, other))).toBe(ErrorCodes.SIG_INVALID);
  });

  it('BitstringStatusListCredential 型でない VC は 3002', async () => {
    const jwt = issueCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        id: URL1,
        issuer: ISSUER,
        issuanceDate: '2025-12-31T23:43:20Z',
        credentialSubject: { id: `${URL1}#list`, type: 'BitstringStatusList' },
      },
      SIGNER,
      { nowSeconds: IAT },
    );

    expect(await codeOf(verifyBitstringStatusListCredential(jwt, URL1, verifyWith()))).toBe(
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('最小長未満の encodedList を持つ（署名は有効な）リスト VC は 3002（STATUS_LIST_LENGTH_ERROR）', async () => {
    const short = `u${base64urlnopad.encode(gzipSync(new Uint8Array(1024)))}`;
    const jwt = issueCredential(
      {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        id: URL1,
        issuer: ISSUER,
        issuanceDate: '2025-12-31T23:43:20Z',
        credentialSubject: {
          id: `${URL1}#list`,
          type: 'BitstringStatusList',
          statusPurpose: 'revocation',
          encodedList: short,
        },
      },
      SIGNER,
      { nowSeconds: IAT },
    );

    expect(await codeOf(verifyBitstringStatusListCredential(jwt, URL1, verifyWith()))).toBe(
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });

  it('取得失敗はそのまま伝播する（fail-closed）', async () => {
    const boom = new Error('network unreachable');

    const error = await resolveBitstringStatus(entry, {
      fetchCredential: async () => {
        throw boom;
      },
      verify: verifyWith(),
    }).catch((e: unknown) => e);

    expect(error).toBe(boom);
  });

  it('fetchCredential が関数でない / 文字列を返さない / URL が無いエントリは 3002', async () => {
    const jwt = await publish(list);
    const verify = verifyWith();

    expect(
      await codeOf(resolveBitstringStatus(entry, { fetchCredential: 1 as never, verify })),
    ).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(
      await codeOf(
        resolveBitstringStatus(entry, { fetchCredential: async () => 1 as never, verify }),
      ),
    ).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(
      await codeOf(resolveBitstringStatus({}, { fetchCredential: async () => jwt, verify })),
    ).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });
});
