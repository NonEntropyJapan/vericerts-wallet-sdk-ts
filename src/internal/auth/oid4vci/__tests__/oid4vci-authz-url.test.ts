/**
 * 認可 URL 構築のテスト（`buildAuthorizationUrl`）。
 *
 * PAR で取得した `request_uri` と `client_id` だけを front-channel へ載せること、既存クエリを
 * 壊さないこと、非 HTTPS・空パラメータを 8010 で拒否することを固定する。PAR 応答を入力に取る
 * エンドツーエンド経路も含めるため、fetch スタブは `par-fixtures.ts` を共有する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { buildAuthorizationUrl } from '../oid4vci-authz-url.js';
import { pushAuthorizationRequest } from '../par/index.js';
import {
  AUTHORIZATION_ENDPOINT,
  baseRequest,
  type FetchCall,
  stubFetchOk,
  VALID_PAR_BODY,
} from './par/par-fixtures.js';

describe('request_uri 解決（buildAuthorizationUrl）', () => {
  it('client_id と request_uri を持つ認可 URL を構築する', () => {
    const url = buildAuthorizationUrl(
      AUTHORIZATION_ENDPOINT,
      'wallet-client',
      VALID_PAR_BODY.request_uri,
    );
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe(AUTHORIZATION_ENDPOINT);
    expect(parsed.searchParams.get('client_id')).toBe('wallet-client');
    expect(parsed.searchParams.get('request_uri')).toBe(VALID_PAR_BODY.request_uri);
  });

  it('PAR 応答の request_uri をそのまま認可 URL に載せられる（エンドツーエンド）', async () => {
    const calls: FetchCall[] = [];
    const res = await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls)));
    const url = buildAuthorizationUrl(AUTHORIZATION_ENDPOINT, 'wallet-client', res.request_uri);
    expect(new URL(url).searchParams.get('request_uri')).toBe(VALID_PAR_BODY.request_uri);
  });

  it('既存クエリを保ちつつ client_id / request_uri を追加する', () => {
    const url = buildAuthorizationUrl(
      'https://issuer.example.com/authorize?ui_locales=ja',
      'wallet-client',
      'urn:req:1',
    );
    const params = new URL(url).searchParams;
    expect(params.get('ui_locales')).toBe('ja');
    expect(params.get('client_id')).toBe('wallet-client');
    expect(params.get('request_uri')).toBe('urn:req:1');
  });

  it('非 HTTPS の authorizationEndpoint は TOKEN_REQUEST_FAILED(8010) になる', () => {
    expect(() =>
      buildAuthorizationUrl('http://issuer.example.com/authorize', 'c', 'urn:req:1'),
    ).toThrow(VericertsError);
    try {
      buildAuthorizationUrl('http://issuer.example.com/authorize', 'c', 'urn:req:1');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    }
  });

  it('client_id / request_uri が空なら TOKEN_REQUEST_FAILED(8010) になる', () => {
    expect(() => buildAuthorizationUrl(AUTHORIZATION_ENDPOINT, '', 'urn:req:1')).toThrow(
      VericertsError,
    );
    expect(() => buildAuthorizationUrl(AUTHORIZATION_ENDPOINT, 'c', '   ')).toThrow(VericertsError);
  });
});
