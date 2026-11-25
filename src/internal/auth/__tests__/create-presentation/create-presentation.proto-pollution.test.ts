/**
 * `createPresentation`（`internal/auth/create-presentation/index.ts`）
 * が `Object.prototype` 汚染下でも own-property 規律を守ることの回帰テスト。
 *
 * 姉妹関数 `oid4vp.ts` の `buildVPTokenEntry` は 同種の問題を `ownProperty` 化して
 * 修正済みだが、本関数はその規律から回帰していた。実証する欠陥は 3 つ:
 *
 * 1. `request.clientId` / `request.nonce` を鎖読みすると、それらを持たない `request` でも
 *    `Object.prototype` の汚染値が**署名済み JWT-VP** の `aud` / `nonce` として載る（audience /
 *    リプレイ防止バインドの乗っ取り）。own 限定で読んだうえで、どちらかが `undefined`
 *    （own プロパティとして存在しない）なら署名せず `OID4VP_REQUEST_PARSE_FAILED`（8030）で
 *    拒否する（fail-closed）。
 * 2. `opts.checkLoa` を鎖読みすると、`opts={}` の正当な呼び出しでも継承関数が実行される
 *    （LoA ゲート用フックが未指定でも発火する fail-open）。
 * 3. 候補 VC / 選択 VC の `id` を鎖読みすると、own `id` を持たない（＝要求に合致しない）VC が
 *    `Object.prototype.id` 汚染で候補集合の判定を素通りし、`credentialSubject` ごと VP に
 *    埋め込まれる（開示制御のバイパス）。
 * 4. `matchCredentialsAgainstRequest`（`match-credentials.ts`）内の `request.dcqlQuery` /
 *    `request.presentationDefinition` を鎖読みすると、どちらも own に持たない要求（本来は候補集合が
 *    空で 3080 拒否のはず）が `Object.prototype` 汚染下で候補集合を持ってしまい、`createPresentation`
 *    がその候補集合に対して署名済み VP を返してしまう（単体の回帰テストは `match-credentials/match-credentials.proto-pollution.test.ts`、本ファイルでは
 *    `createPresentation` 経由のエンドツーエンドで「空集合のまま扱われる（＝拒否される）」ことを
 *    固定する）。
 */

import { describe, expect, it } from 'bun:test';
import {
  pollutePrototype,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { createPrivateKeySigner } from '../../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createPresentation } from '../../create-presentation/index.js';
import { parsePresentationRequest } from '../../jar/index.js';
import type { PresentationRequest } from '../../request.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';
const HOLDER_DID = 'did:example:holder';
const ATTACKER_CLIENT_ID = 'https://attacker.evil';
const ATTACKER_NONCE = 'attacker-chosen-nonce';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');

/** DCQL クエリを含む直接形式の requestURI を組み立てる。 */
function buildRequestUri(): string {
  const dcql = {
    credentials: [
      {
        id: 'degree',
        format: 'jwt_vc_json',
        claims: [{ path: ['credentialSubject', 'name'], values: ['Bob'] }],
      },
    ],
  };
  const search = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(dcql),
  });
  return `openid4vp://?${search.toString()}`;
}

function makeVc(id: string, name: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

describe('createPresentation — Object.prototype 汚染下での own-property 規律', () => {
  it('request.clientId / request.nonce を own に持たない場合、汚染値を使わず OID4VP_REQUEST_PARSE_FAILED(8030) で拒否する', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUri());
    // `clientId` / `nonce` を own プロパティから除いた request（スプレッドは own 列挙プロパティ
    // のみをコピーするため、除外したキーは prototype 経由でしか読めなくなる）。
    const { clientId: _clientId, nonce: _nonce, ...rest } = request;
    const strippedRequest = rest as unknown as PresentationRequest;

    // own に無い以上「未指定」として扱われ、汚染値を aud/nonce として使うのではなく
    // fail-closed に 8030 で拒否する。
    await expect(
      withPollutedPrototypeAsync({ clientId: ATTACKER_CLIENT_ID, nonce: ATTACKER_NONCE }, () =>
        createPresentation(strippedRequest, [bob], [bob], SIGNER, HOLDER_DID),
      ),
    ).rejects.toThrow(new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED));
  });

  it('opts={} でも Object.prototype.checkLoa 汚染下で継承フックが発火しない', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUri());
    const calls: unknown[] = [];
    const restore = pollutePrototype({
      checkLoa: (selectedVCs: unknown) => {
        calls.push(selectedVCs);
      },
    });

    try {
      await createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID, {});
    } finally {
      restore();
    }

    expect(calls).toHaveLength(0);
  });

  it('own id を持たない VC は Object.prototype.id 汚染下でも候補集合の判定を通らず 3080 になる（開示制御バイパス防止）', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const request = await parsePresentationRequest(buildRequestUri());
    // 要求に合致しない VC から own `id` を落とした入力（攻撃者は `Object.prototype.id` を
    // 正規候補 `bob` の id に汚染し、own id の無い任意の VC を候補扱いさせようとする）。
    const { id: _id, ...noOwnId } = bob;
    const forgedVc = noOwnId as unknown as VerifiableCredential;

    await withPollutedPrototypeAsync({ id: 'urn:vc:bob' }, async () => {
      await expect(
        createPresentation(request, [forgedVc], [bob], SIGNER, HOLDER_DID),
      ).rejects.toThrow(new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH));
    });
  });

  it('dcql_query も presentation_definition も own に持たない要求は、Object.prototype.dcqlQuery 汚染下でも候補集合が空のまま VC_REQUIREMENT_MISMATCH(3080) で拒否される', async () => {
    const bob = makeVc('urn:vc:bob', 'Bob');
    const search = new URLSearchParams({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
    });
    const request = await parsePresentationRequest(`openid4vp://?${search.toString()}`);
    expect(Object.hasOwn(request, 'dcqlQuery')).toBe(false);

    await withPollutedPrototypeAsync(
      { dcqlQuery: { credentials: [{ id: 'degree', format: 'jwt_vc_json' }] } },
      async () => {
        await expect(createPresentation(request, [bob], [bob], SIGNER, HOLDER_DID)).rejects.toThrow(
          new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH),
        );
      },
    );
  });
});
