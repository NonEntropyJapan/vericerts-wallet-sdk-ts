/**
 * ファサード `receiveCredential` の pre-authorized_code 経路における DPoP 送出
 *
 * Token Request と Credential Request で送る DPoP proof を検証する（RFC 9449 §5 / §7.1）。
 *
 * 検証する不変条件は 2 つある:
 *
 * 1. **Token Request にも proof が載る**。RFC 9449 §5 はグラント種別を問わないので
 *    pre-authorized_code 経路でも DPoP を利用できる。`htu` は送信先ごとの束縛（§4.3）なので
 *    Token Endpoint 用と Credential Endpoint 用を**別に生成する**。
 * 2. **手順 12 の送出形式は `createDpopProof` の指定有無ではなく Token Response の `token_type`
 *    で決める**。Bearer 束縛トークンに `Authorization: DPoP` を付けると RFC 9449
 *    §7.1 準拠の Issuer が拒否するため、proof 生成関数を渡していても（= Token Request で DPoP を
 *    要求していても）AS が `token_type: "Bearer"` を返したなら Bearer で送らなければならない。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../../errors.js';
import type { DpopProof } from '../../../../dpop/dpop-common.js';
import { receiveCredential } from '../../receive.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from '../facade-fixtures.js';

/** `htu` を記録しつつ proof 文字列を返すスタブ（`DpopProof` はコンパクト JWS 文字列の別名）。 */
function recordingDpop(htus: string[]): (htu: string) => DpopProof {
  return (htu) => {
    htus.push(htu);
    return `dpop-proof-for-${htu}`;
  };
}

/** `token_type` を指定した pre-authorized_code 経路の成功スタブ。 */
function stubWithTokenType(tokenType: string): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(tokenType),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential: pre-authorized_code 経路の token_type 分岐', () => {
  test('Bearer 束縛トークンには createDpopProof を渡しても DPoP スキームを付けない', async () => {
    const stub = stubWithTokenType('Bearer');
    const htus: string[] = [];
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { createDpopProof: recordingDpop(htus) }),
    );
    const headers = stub.callTo(CREDENTIAL_URL)?.headers;
    expect(headers?.Authorization).toStartWith('Bearer ');
    expect(headers?.DPoP).toBeUndefined();
    // Token Request では proof を生成するが、AS が Bearer を返したので手順 12 用の
    // proof は生成しない。RFC 9449 §5 の送出は束縛の**要求**であって、AS が Bearer を返す選択は
    // 正当であるため。
    expect(htus).toEqual([TOKEN_URL]);
  });

  test('DPoP 束縛トークンには Credential Endpoint を htu とする proof を載せる', async () => {
    const stub = stubWithTokenType('DPoP');
    const htus: string[] = [];
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { createDpopProof: recordingDpop(htus) }),
    );
    const headers = stub.callTo(CREDENTIAL_URL)?.headers;
    expect(headers?.Authorization).toStartWith('DPoP ');
    expect(headers?.DPoP).toBe(`dpop-proof-for-${CREDENTIAL_URL}`);
    // RFC 9449 §4.3 の `htu` 束縛は送信先ごと。Token Endpoint の proof は再利用せず、
    // Token → Credential の順で `htu` ごとに 1 本ずつ生成する。
    expect(htus).toEqual([TOKEN_URL, CREDENTIAL_URL]);
  });

  test('token_type は大文字小文字を区別しない（RFC 6749 §5.1）', async () => {
    const stub = stubWithTokenType('dpop');
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { createDpopProof: recordingDpop([]) }),
    );
    expect(stub.callTo(CREDENTIAL_URL)?.headers.Authorization).toStartWith('DPoP ');
  });

  test('DPoP 束縛トークンなのに proof 生成関数が無ければ 8020 で落とす（fail-closed）', async () => {
    const stub = stubWithTokenType('DPoP');
    await expect(
      receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub)),
    ).rejects.toMatchObject({ context: { reason: 'dpop_proof_required' } });
    // access_token を平文で 1 度も送らない。
    expect(stub.callTo(CREDENTIAL_URL)).toBeUndefined();
  });
});

describe('receiveCredential: pre-authorized_code 経路の Token Request DPoP', () => {
  test('createDpopProof を渡すと Token Request に DPoP ヘッダが載る', async () => {
    const stub = stubWithTokenType('DPoP');
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { createDpopProof: recordingDpop([]) }),
    );
    const call = stub.callTo(TOKEN_URL);
    expect(call?.headers.DPoP).toBe(`dpop-proof-for-${TOKEN_URL}`);
    // RFC 9449 §5: proof は body ではなくヘッダで送る。
    expect(new URLSearchParams(call?.body ?? '').has('dpop')).toBe(false);
  });

  test('Token Request の proof は htu = Token Endpoint で生成される（RFC 9449 §4.3）', async () => {
    const stub = stubWithTokenType('DPoP');
    const htus: string[] = [];
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { createDpopProof: recordingDpop(htus) }),
    );
    // Issuer Metadata の `token_endpoint` がそのまま `htu` になること。PAR / Credential 用の
    // proof を使い回すと `htu` が食い違い、AS が §4.3 の HTTP 束縛検証で拒否する。
    // 期待値は `htus[0]` から導かず **`TOKEN_URL` リテラル**で書く（`htus[0]` を使うと上の行の
    // 言い換えになり、両方が同じ誤った値になった退行を検出できない）。
    expect(htus[0]).toBe(TOKEN_URL);
    expect(stub.callTo(TOKEN_URL)?.headers.DPoP).toBe(`dpop-proof-for-${TOKEN_URL}`);
  });

  test.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('createDpopProof が%sを返したら 8010 で拒否し Token Request を送らない', async (_l, proof) => {
    const stub = stubWithTokenType('DPoP');
    await expect(
      receiveCredential(
        preAuthorizedOfferURI(),
        facadeDeps(stub, { createDpopProof: () => proof }),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    // 空の `DPoP` ヘッダは AS 側で形式不正になるだけなので入口で落とす。pre-authorized_code も
    // 平文で 1 度も送らない（`oid4vci-token.ts` の送信前検査が facade 経由でも効くこと）。
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  test('createDpopProof 未指定なら Token Request に DPoP ヘッダを出さない（既存挙動）', async () => {
    const stub = stubWithTokenType('Bearer');
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    // Token Request が実際に起きたことを先に固定する（`callTo` は未記録なら `undefined` を返し、
    // `Object.hasOwn({}, …)` は false になるので、送信自体が消えた退行も通ってしまう）。
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
    // 空ヘッダも出さない（AS が DPoP 利用の意図ありと解釈して形式不正で落としうる）。
    expect(Object.hasOwn(stub.callTo(TOKEN_URL)?.headers ?? {}, 'DPoP')).toBe(false);
  });
});
