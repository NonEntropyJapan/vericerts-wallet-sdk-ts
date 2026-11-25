/**
 * SD-JWT VC の選択的開示、予約済みクレーム名とステータスリストの添字を検証する。
 *
 * draft-ietf-oauth-sd-jwt-vc §2.2.2.3 は `vct#integrity` / `aka_vcts` も選択的開示の対象にしてはならない。
 * RFC 9901 §4.2.1 / §7.1 3.c.ii.2 はオブジェクトプロパティ Disclosure の名前が `_sd` / `...` のとき拒否する。
 * Token Status List の `idx` は非負整数。resolver（`assertIndex`）に届く前に検証時点で 3010 にする。
 * 公開 API（`src/index.ts` の re-export と Wallet ファサード）経由の到達もここで確認する。
 */

import { describe, expect, it } from 'bun:test';
import {
  createSdJwt,
  decodeDisclosure,
  encodeDisclosure,
  parseSdJwt,
  selectDisclosures,
  toQueryableFromSdJwt,
  verifySdJwt,
} from '../../../../../index.js';
import { MemoryStorage } from '../../../../../storage/storage.js';
import { createWallet } from '../../../../../wallet/factory.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { NON_DISCLOSABLE_CLAIMS } from '../../non-disclosable-claims.js';
import { ISSUER_JWK, ISSUER_SIGNER, reissueWithPayload, VCT } from '../hardening/shared.js';
import { expectRejected, NOW, rawDisclosure } from './fixtures.js';

const REJECTED = new VericertsError(ErrorCodes.SIG_INVALID);

describe('aka_vcts / vct#integrity は選択的開示の対象外', () => {
  it('NON_DISCLOSABLE_CLAIMS に含まれる', () => {
    expect(NON_DISCLOSABLE_CLAIMS).toContain('aka_vcts');
    expect(NON_DISCLOSABLE_CLAIMS).toContain('vct#integrity');
  });

  for (const name of ['aka_vcts', 'vct#integrity']) {
    it(`${name} の Disclosure は 3010（検証 API）`, () => {
      const d = encodeDisclosure(name, ['https://example.com/old'], 'salt-v2');
      expectRejected({ _sd: [d.digest] }, [d.encoded]);
    });
  }

  it('createSdJwt（発行）は disclosureClaims に挙げても `aka_vcts` を平文に残す', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['aka_vcts'],
      claims: { aka_vcts: ['https://example.com/old'] },
      nowSeconds: NOW,
    });
    expect(parseSdJwt(sdJwt).disclosures).toHaveLength(0);
    const verified = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(verified.claims.aka_vcts).toEqual(['https://example.com/old']);
  });
});

describe('オブジェクトプロパティ Disclosure の名前が `_sd` / `...` は拒否', () => {
  for (const name of ['_sd', '...']) {
    it(`decodeDisclosure は名前 ${name} の 3 要素 Disclosure を 3010 で拒否する`, () => {
      const { encoded } = rawDisclosure(['salt', name, 'v']);
      expect(() => decodeDisclosure(encoded)).toThrow(REJECTED);
    });

    it(`verifySdJwt は名前 ${name} の Disclosure を同梱した提示を 3010 で拒否する`, () => {
      const d = rawDisclosure(['salt', name, ['x']]);
      expectRejected({ _sd: [d.digest] }, [d.encoded]);
    });

    it(`入れ子の \`_sd\` が指す名前 ${name} の Disclosure も 3010`, () => {
      const d = rawDisclosure(['salt', name, 'v']);
      expectRejected({ nested: { _sd: [d.digest] } }, [d.encoded]);
    });
  }

  it('Wallet.issueSdJwt（公開ファサード）は名前 `...` の Disclosure を発行前に 3010 で拒否する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
    const key = await wallet.deriveKey("m/44'/60'/0'/0/0");
    const did = (await wallet.createDID('key', { keyID: key.id })).id;
    const issue = (claim: string) =>
      wallet.issueSdJwt(key.id, {
        vct: VCT,
        issuer: did,
        disclosureClaims: [claim],
        claims: { [claim]: 'v' },
      });
    // 発行側の gdpr-guard が `decodeDisclosure` で自己検査するため、検証側が拒否する SD-JWT は
    // そもそも発行できない（修正前は `...` の Disclosure が発行・検証とも通っていた）。
    await expect(issue('...')).rejects.toThrow(REJECTED);
    expect((await wallet.verifySdJwt(await issue('name'))).claims.name).toBe('v');
  });
});

describe('status.status_list.idx は非負整数（3010）', () => {
  const verifyWithIdx = (idx: unknown) =>
    verifySdJwt(
      reissueWithPayload(
        { vct: VCT, iat: NOW, status: { status_list: { idx, uri: 'https://i.example/s/1' } } },
        [],
      ),
      { issuerKey: ISSUER_JWK, nowSeconds: NOW },
    );

  for (const [label, idx] of [
    ['負数', -1],
    ['小数', 1.5],
    ['文字列', '1'],
    ['null', null],
  ] as const) {
    it(`idx が ${label} なら verifySdJwt が 3010`, () => {
      expect(() => verifyWithIdx(idx)).toThrow(REJECTED);
    });
  }

  it('idx が 0 / 大きな整数なら受理し status に載る', () => {
    expect(verifyWithIdx(0).status?.status_list.idx).toBe(0);
    expect(verifyWithIdx(131_072).status?.status_list.idx).toBe(131_072);
  });

  it('Wallet.verifySdJwt（公開ファサード）も idx が負数の SD-JWT を 3010 で拒否する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
    const key = await wallet.deriveKey("m/44'/60'/0'/0/0");
    const did = (await wallet.createDID('key', { keyID: key.id })).id;
    const issue = (idx: number) =>
      wallet.issueSdJwt(key.id, {
        vct: VCT,
        issuer: did,
        disclosureClaims: [],
        claims: {},
        status: { status_list: { idx, uri: 'https://i.example/s/1' } },
      });
    await expect(wallet.verifySdJwt(await issue(-1))).rejects.toThrow(REJECTED);
    expect((await wallet.verifySdJwt(await issue(7))).status?.status_list.idx).toBe(7);
  });
});

describe('公開 API は 2 要素 Disclosure を同梱した SD-JWT を扱える', () => {
  it('parseSdJwt / selectDisclosures は 2 要素 Disclosure を保持し、クレーム名指定では選択しない', () => {
    const arr = rawDisclosure(['salt', 'FR']);
    const prop = encodeDisclosure('name', 'Alice', 'salt-n');
    const sdJwt = reissueWithPayload(
      { vct: VCT, iat: NOW, _sd: [prop.digest], nat: [{ '...': arr.digest }] },
      [prop.encoded, arr.encoded],
    );
    const parts = parseSdJwt(sdJwt);
    expect(parts.disclosures.map((d) => d.claimName)).toEqual(['name', undefined]);
    const presented = selectDisclosures(sdJwt, ['name']);
    expect(parseSdJwt(presented).disclosures.map((d) => d.encoded)).toEqual([prop.encoded]);
  });

  it('toQueryableFromSdJwt（DCQL 正規化）は 2 要素 Disclosure を最上位クレームにせず、3 要素だけをマージする', () => {
    const arr = rawDisclosure(['salt', 'FR']);
    const prop = encodeDisclosure('name', 'Alice', 'salt-n');
    const sdJwt = reissueWithPayload(
      { vct: VCT, iat: NOW, _sd: [prop.digest], nat: [{ '...': arr.digest }] },
      [prop.encoded, arr.encoded],
    );
    const { claims } = toQueryableFromSdJwt(sdJwt);
    expect(claims.name).toBe('Alice');
    expect(Object.keys(claims)).not.toContain('undefined');
    expect(Object.keys(claims).sort()).toEqual(['iat', 'name', 'nat', 'vct']);
  });
});
