/**
 * `presentPIDCredential` / `presentEAACredential` の `request_uri` 参照形式（JAR）対応の
 * 回帰テスト。
 *
 * 従来、提示ファサードの実体は同期の `parseAuthorizationRequest` しか呼んでおらず、
 * `request_uri` を含む提示要求を `8030`（`reason: "request_uri_reference"`）で拒否していた。
 * HAIP 1.0 §5.1 はリダイレクト経由の OpenID4VP 提示要求に、署名済みの JAR を
 * `request_uri` で指定するよう求めている。この形式の要求を両方の提示ファサードで検証する。
 *
 * ここで固定するのは 3 点である。
 *
 * 1. `request_uri` 単独形式が拒否されず、取得 → DCQL 相当の評価 → 送信まで通ること
 * 2. `fetchImpl` の注入が **JAR 取得にも**効くこと（グローバル `fetch` へ漏れないこと）
 * 3. 参照形式が 署名検証を経由すること（Trust Anchor 未設定・署名不正は拒否）
 */

import { describe, expect, test } from 'bun:test';
import { presentEAACredential as publicPresentEAA } from '../../../../../exports/experimental/eudi.js';
import { parseSdJwt } from '../../../../credential/sdjwt/sdjwt.js';
import { ErrorCodes, type VericertsError } from '../../../../errors.js';
import type { SubmitFetchLike } from '../../../oid4vp/oid4vp-submit.js';
import { presentEAACredential, presentPIDCredential } from '../present.js';
import type { PresentDeps } from '../types.js';
import {
  buildReferenceRequestURI,
  buildReferenceRequestURIWithClientId,
  createJarSubmitStub,
  JAR_REQUEST_URI,
  jarPresentDeps,
  makePresentationJarSigner,
  signPresentationJar,
} from './jar-presentation-fixtures.js';
import {
  EAA_VCT,
  eaaCredential,
  HOLDER_DID,
  holderSigner,
  pidCredential,
  RESPONSE_URI,
  submittedVpToken,
} from './presentation-fixtures.js';

const VERIFIER = makePresentationJarSigner();
const SIGNED_JAR = signPresentationJar(VERIFIER);

async function expectReason(promise: Promise<unknown>, reason: string): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect(error.context).toMatchObject({ reason });
  }
}

describe('presentPIDCredential: request_uri 参照形式', () => {
  test('request_uri 単独形式が拒否されず、取得・評価・送信まで通る', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    const vp = await presentPIDCredential(
      buildReferenceRequestURI(),
      ['family_name', 'birth_date'],
      pidCredential(),
      jarPresentDeps(stub.fetchImpl, VERIFIER.anchors),
    );

    // JAR を注入した fetch で取得している（グローバル fetch へ漏れていない）。
    expect(stub.fetchedRequestUris).toEqual([JAR_REQUEST_URI]);
    // Request Object の `response_uri` へ送信している（クエリ側の値は存在しない）。
    expect(stub.calls).toHaveLength(1);
    expect(stub.calls[0]?.url).toBe(RESPONSE_URI);
    const vpToken = submittedVpToken(stub.calls[0]);
    expect(
      parseSdJwt(vpToken)
        .disclosures.map((d) => d.claimName)
        .sort(),
    ).toEqual(['birth_date', 'family_name']);
    // Key Binding JWT は Request Object の nonce / client_id からバインドされる。
    expect(parseSdJwt(vpToken).keyBinding).toBeString();
    expect(vp.verifiableCredential).toEqual([vpToken]);
    expect(vp.holder).toBe(HOLDER_DID);
  });

  test('client_id 併記の参照形式も処理される', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    await presentPIDCredential(
      buildReferenceRequestURIWithClientId(),
      ['age_over_18'],
      pidCredential(),
      jarPresentDeps(stub.fetchImpl, VERIFIER.anchors),
    );
    expect(stub.calls).toHaveLength(1);
  });

  test('deep link の client_id が Request Object と食い違えば送信しない', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    await expectReason(
      presentPIDCredential(
        buildReferenceRequestURIWithClientId('https://attacker.example'),
        ['age_over_18'],
        pidCredential(),
        jarPresentDeps(stub.fetchImpl, VERIFIER.anchors),
      ),
      'jar_client_id_mismatch',
    );
    // 提示 UI へ進む前に中断する = VP Token は 1 バイトも出さない。
    expect(stub.calls).toHaveLength(0);
  });
});

describe('presentEAACredential: request_uri 参照形式', () => {
  test('公開 API は private field を持つ class の fetchImpl を JAR GET と送信 POST に使う', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    class PresentationDeps implements PresentDeps {
      readonly signer = holderSigner();
      readonly jarTrust = { trustAnchors: VERIFIER.anchors };
      #calls: string[] = [];

      fetchImpl(url: string, init: Parameters<SubmitFetchLike>[1]): Promise<Response> {
        this.#calls.push(init.method);
        return stub.fetchImpl(url, init);
      }

      get calls(): readonly string[] {
        return this.#calls;
      }
    }
    const deps = new PresentationDeps();

    const vp = await publicPresentEAA(buildReferenceRequestURI(), EAA_VCT, [eaaCredential()], deps);

    expect(deps.calls).toEqual(['GET', 'POST']);
    expect(stub.fetchedRequestUris).toEqual([JAR_REQUEST_URI]);
    expect(stub.calls.map((call) => call.url)).toEqual([RESPONSE_URI]);
    expect(vp.verifiableCredential).toEqual([submittedVpToken(stub.calls[0])]);
  });

  test('fetchImpl の prototype getter は一度だけ読む', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    let reads = 0;
    class GetterDeps implements PresentDeps {
      readonly signer = holderSigner();
      readonly jarTrust = { trustAnchors: VERIFIER.anchors };

      get fetchImpl(): SubmitFetchLike {
        reads += 1;
        return stub.fetchImpl;
      }
    }

    await publicPresentEAA(
      buildReferenceRequestURI(),
      EAA_VCT,
      [eaaCredential()],
      new GetterDeps(),
    );

    expect(reads).toBe(1);
    expect(stub.fetchedRequestUris).toHaveLength(1);
    expect(stub.calls).toHaveLength(1);
  });

  test('request_uri 単独形式が拒否されず、取得・評価・送信まで通る', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    const vp = await presentEAACredential(
      buildReferenceRequestURI(),
      EAA_VCT,
      [eaaCredential()],
      jarPresentDeps(stub.fetchImpl, VERIFIER.anchors),
    );
    expect(stub.fetchedRequestUris).toEqual([JAR_REQUEST_URI]);
    expect(stub.calls).toHaveLength(1);
    expect(stub.calls[0]?.url).toBe(RESPONSE_URI);
    expect(vp.verifiableCredential).toEqual([submittedVpToken(stub.calls[0])]);
  });
});

describe('参照形式は JAR 署名検証を経由する', () => {
  test('Trust Anchor 未設定では取得も送信もしない（fail-closed）', async () => {
    // 検証できない Request Object を提示フローへ流し込まない。検証漏れがファサード経路に
    // 残っていれば、ここで署名を検証せず送信まで通ってしまう。
    const stub = createJarSubmitStub(SIGNED_JAR);
    await expectReason(
      presentPIDCredential(
        buildReferenceRequestURI(),
        ['age_over_18'],
        pidCredential(),
        jarPresentDeps(stub.fetchImpl),
      ),
      'jar_trust_anchors_unconfigured',
    );
    expect(stub.fetchedRequestUris).toHaveLength(0);
    expect(stub.calls).toHaveLength(0);
  });

  test('別の Trust Anchor しか持たない場合は拒否する', async () => {
    const foreign = makePresentationJarSigner();
    const stub = createJarSubmitStub(SIGNED_JAR);
    await expectReason(
      presentEAACredential(
        buildReferenceRequestURI(),
        EAA_VCT,
        [eaaCredential()],
        jarPresentDeps(stub.fetchImpl, foreign.anchors),
      ),
      'rp_cert_untrusted',
    );
    expect(stub.calls).toHaveLength(0);
  });

  test('署名を保ったままペイロードを差し替えた Request Object を拒否する', async () => {
    const tampered = (() => {
      const [header, , signature] = SIGNED_JAR.split('.') as [string, string, string];
      const evil = Buffer.from(
        JSON.stringify({
          iss: 'https://verifier.example.eu',
          response_type: 'vp_token',
          client_id: 'https://verifier.example.eu',
          response_mode: 'direct_post',
          response_uri: 'https://verifier.example.eu/evil',
          nonce: 'attacker-nonce',
          state: 'attacker-state',
        }),
      ).toString('base64url');
      return `${header}.${evil}.${signature}`;
    })();
    const stub = createJarSubmitStub(tampered);
    await expectReason(
      presentPIDCredential(
        buildReferenceRequestURI(),
        ['age_over_18'],
        pidCredential(),
        jarPresentDeps(stub.fetchImpl, VERIFIER.anchors),
      ),
      'jar_signature_invalid',
    );
    expect(stub.calls).toHaveLength(0);
  });
});

describe('直接形式は従来どおり', () => {
  test('Trust Anchor 未設定でも直接形式は処理される', async () => {
    const stub = createJarSubmitStub(SIGNED_JAR);
    const params = new URLSearchParams({
      response_type: 'vp_token',
      client_id: 'https://verifier.example.eu',
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce: 'n-direct-0123456789abcdef',
      state: 'state-direct',
    });
    await presentPIDCredential(
      `openid4vp://?${params.toString()}`,
      ['age_over_18'],
      pidCredential(),
      jarPresentDeps(stub.fetchImpl),
    );
    // HTTP 取得は発生せず、送信だけが起きる。
    expect(stub.fetchedRequestUris).toHaveLength(0);
    expect(stub.calls).toHaveLength(1);
  });
});
