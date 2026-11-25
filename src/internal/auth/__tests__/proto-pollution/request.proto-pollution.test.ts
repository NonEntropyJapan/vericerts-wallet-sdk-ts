/**
 * `Object.prototype` 汚染下でも Authorization Request に汚染値が載らないことの回帰テスト
 *
 * JAR に `client_metadata` がなければ、`parseJarRequest` の戻り値は `clientMetadata` プロパティを持たない。
 *
 * 欠陥時の挙動: JAR JWT の payload は `JSON.parse` 済みの生オブジェクトで、`payload.client_metadata`
 * を直接読むと **そのクレームを持たない JAR でも `Object.prototype.client_metadata` の汚染値が
 * 「Verifier が告知したメタデータ」として `PresentationRequest` の自身のプロパティへ昇格する**。
 * 下流（`oid4vp-submit.ts`）が `Object.hasOwn` で告知有無を判定しても、昇格後は汚染値と正当な
 * 告知を区別できず、vp_token が攻撃者の鍵で暗号化される。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { createSdJwt } from '../../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { parseJarRequest } from '../../request.js';

const CLIENT_ID = 'https://verifier.example';
const RESPONSE_URI = `${CLIENT_ID}/callback`;
const JAR_SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');

/** 攻撃者の暗号化鍵だけを載せた `client_metadata`。 */
const ATTACKER_METADATA = {
  authorization_encrypted_response_alg: 'ECDH-ES',
  jwks: { keys: [{ kty: 'EC', crv: 'P-256', use: 'enc', kid: 'attacker', x: 'eA', y: 'eQ' }] },
};

/** OID4VP パラメータを payload に持つ JAR JWT（コンパクト JWS）を実署名で作る。 */
function buildJarJwt(extra: Record<string, unknown> = {}): string {
  const sdJwt = createSdJwt(JAR_SIGNER, {
    vct: 'jar',
    disclosureClaims: [],
    claims: {
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post.jwt',
      response_uri: RESPONSE_URI,
      nonce: 'n-1-0123456789abcdefghij',
      state: 's-1',
      ...extra,
    },
  });
  return sdJwt.split('~')[0] as string;
}

describe('parseJarRequest: Object.prototype 汚染', () => {
  it('client_metadata を持たない JAR で汚染値が Request に昇格しない', () => {
    const jwt = buildJarJwt();
    const request = withPollutedPrototype({ client_metadata: ATTACKER_METADATA }, () =>
      parseJarRequest(jwt),
    );
    // 「告知なし」を下流が `Object.hasOwn` で判定できること（自身のプロパティが増えていない）。
    expect(Object.hasOwn(request, 'clientMetadata')).toBe(false);
    expect(request.clientMetadata).toBeUndefined();
  });

  it('dcql_query / presentation_definition / transaction_data / required_loa の汚染も Request に載らない', () => {
    const jwt = buildJarJwt();
    const request = withPollutedPrototype(
      {
        dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
        presentation_definition: { id: 'polluted' },
        transaction_data: ['cG9sbHV0ZWQ'],
        required_loa: 'high',
      },
      () => parseJarRequest(jwt),
    );
    expect(Object.hasOwn(request, 'dcqlQuery')).toBe(false);
    expect(Object.hasOwn(request, 'presentationDefinition')).toBe(false);
    expect(Object.hasOwn(request, 'transactionData')).toBe(false);
    // `required_loa` を持たない JAR が汚染値で `high` を要求扱いになると、後続の LoA 判定フック
    // （`wallet/credential/create-presentation.ts` の `buildLoaCheck`）が
    // 本来発火しないはずの LOA_MISMATCH を送出しうる（未告知の要求が汚染値で成立する fail-open）。
    expect(Object.hasOwn(request, 'requiredLoA')).toBe(false);
    expect(request.requiredLoA).toBeUndefined();
  });

  it('必須クレームを持たない JAR は汚染値で補完されず 8030 になる', () => {
    // `client_id` を持たない JAR。継承値を拾うと攻撃者が選んだ Verifier 識別子で Request が成立する。
    const sdJwt = createSdJwt(JAR_SIGNER, {
      vct: 'jar',
      disclosureClaims: [],
      claims: {
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',
        response_uri: RESPONSE_URI,
        nonce: 'n-1-0123456789abcdefghij',
        state: 's-1',
      },
    });
    const jwt = sdJwt.split('~')[0] as string;
    const error = withPollutedPrototype({ client_id: CLIENT_ID }, () => {
      try {
        parseJarRequest(jwt);
        return undefined;
      } catch (e: unknown) {
        return e;
      }
    });
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  });

  it('正常系: client_metadata を告知した JAR は汚染下でも自身の値が展開される', () => {
    const legit = {
      authorization_encrypted_response_alg: 'ECDH-ES',
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', use: 'enc', kid: 'k1', x: 'eA', y: 'eQ' }] },
    };
    const jwt = buildJarJwt({ client_metadata: legit });
    const request = withPollutedPrototype({ client_metadata: ATTACKER_METADATA }, () =>
      parseJarRequest(jwt),
    );
    expect(request.clientMetadata).toEqual(legit);
  });

  it('正常系: required_loa を告知した JAR は汚染下でも自身の値が展開される', () => {
    const jwt = buildJarJwt({ required_loa: 'substantial' });
    const request = withPollutedPrototype({ required_loa: 'high' }, () => parseJarRequest(jwt));
    expect(request.requiredLoA).toBe('substantial');
  });
});
