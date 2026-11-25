/**
 * `ReceivedIssuerTrust` の**組み立て**側の不変条件。
 *
 * `issuer-trust/resolve.ts` は純データ 2 メンバ（`issuerTrustAnchors` /
 * `jwtVcIssuerMetadataResolution`）を「値が `undefined` でも own プロパティとして載せる」と規定し、
 * `factory.ts` もその理由を述べているが、**それを固定するテストが無かった**。汚染回帰テストは
 * `verifyReceived` と委譲先の `issuerTrust` 経由の挙動には在るものの、読み取り側が `ownProperty`
 * である以上「組み立てで `undefined` メンバを落とす」リファクタだけでは緑のまま通ってしまう
 * （読み取り側が鎖読みへ退化した瞬間に、`Object.prototype` 汚染下で metadata 経路が黙って
 * 有効化される = 既定の fail-closed 面が開く）。多層防御の片側だけが無検証にならないよう、
 * ここで own プロパティであること自体を押さえる。
 *
 * 経路そのものの回帰は `__tests__/eudi/wallet.eudi.receive-x5c.test.ts`（`x5c`）と
 * `__tests__/eudi/jwt-vc-issuer/`（metadata 経路の opt-in 境界）が持つ。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import type { ReceivedVerifiableCredential } from '../../../internal/auth/index.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { Resolver } from '../../../internal/identity/resolver.js';
import type { QtspServiceCertificate } from '../../../internal/trust/etsi-tsl/index.js';
import {
  buildReceivedIssuerTrust,
  type ReceivedIssuerTrust,
  verifyReceivedCredential,
} from '../../issuer-trust/index.js';

/** 組み立てにしか使わないので、Resolver の中身は問わない（同一性だけを見る）。 */
const RESOLVER = { resolve: async () => undefined } as unknown as Resolver;

/** 汚染値として仕込む Trust Anchor（採られたら一目で分かる目印）。 */
const POLLUTED_ANCHORS = [
  { der: new Uint8Array([1]), status: 'granted' },
] as unknown as readonly QtspServiceCertificate[];

describe('buildReceivedIssuerTrust: 純データメンバの own プロパティ化', () => {
  it('省略された 2 メンバも undefined の own プロパティとして載せる', () => {
    const trust = buildReceivedIssuerTrust({}, RESOLVER, undefined);

    // `in` ではなく `Object.hasOwn` で見る（`in` は鎖を辿るので、落としていても真になり得る）。
    expect(Object.hasOwn(trust, 'issuerTrustAnchors')).toBe(true);
    expect(Object.hasOwn(trust, 'jwtVcIssuerMetadataResolution')).toBe(true);
    expect(trust.issuerTrustAnchors).toBeUndefined();
    expect(trust.jwtVcIssuerMetadataResolution).toBeUndefined();
  });

  it('汚染下で省略しても、鎖読み・own 読みのどちらでも汚染値へ到達しない', () => {
    const trust = withPollutedPrototype(
      {
        issuerTrustAnchors: POLLUTED_ANCHORS,
        jwtVcIssuerMetadataResolution: true,
      },
      () => buildReceivedIssuerTrust({}, RESOLVER, undefined),
    );

    // own プロパティが `undefined` で載っているので、鎖読み（`trust.x`）も汚染値を見ない。
    expect(trust.issuerTrustAnchors).toBeUndefined();
    expect(trust.jwtVcIssuerMetadataResolution).toBeUndefined();
  });

  it('汚染下でも、明示された値は取り違えずにそのまま載せる', () => {
    const anchors = [] as unknown as readonly QtspServiceCertificate[];

    const trust = withPollutedPrototype(
      { issuerTrustAnchors: POLLUTED_ANCHORS, jwtVcIssuerMetadataResolution: false },
      () =>
        buildReceivedIssuerTrust(
          { issuerTrustAnchors: anchors, jwtVcIssuerMetadataResolution: true },
          RESOLVER,
          undefined,
        ),
    );

    expect(trust.issuerTrustAnchors).toBe(anchors);
    expect(trust.jwtVcIssuerMetadataResolution).toBe(true);
  });

  it('DI シーム（resolver / fetch）は渡された値をそのまま持つ', () => {
    const fetchImpl = async () => new Response('{}');

    const trust = buildReceivedIssuerTrust({}, RESOLVER, fetchImpl);

    expect(trust.resolver).toBe(RESOLVER);
    expect(trust.jwtVcIssuerMetadataFetchImpl).toBe(fetchImpl);
  });
});

const b64url = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/**
 * JWT-VC 経路（`format: 'jwt'`）へ入れるための最小の受領結果。
 *
 * `raw` は署名としては不正だが **payload の `iss` まで読める形**にしておく。ここが読めないと
 * `resolveIssuerVerifierKey` が Resolver へ到達する前に落ち、汚染値を掴むかどうかを検証できない
 * （テストがトートロジーになる）。
 */
function jwtReceived(): ReceivedVerifiableCredential {
  const iss = 'did:example:issuer';
  return {
    type: ['VerifiableCredential'],
    issuer: iss,
    issuanceDate: '2020-01-01T00:00:00.000Z',
    claims: {},
    raw: `${b64url({ alg: 'ES256K', typ: 'JWT' })}.${b64url({ iss })}.c2ln`,
    format: 'jwt',
  } as ReceivedVerifiableCredential;
}

describe('verifyReceivedCredential: trust.resolver の読み取り規律', () => {
  // SD-JWT 経路（`resolve.ts`）は `nonObjectPrototypeProperty` で読むのに、JWT-VC 経路だけが
  // `trust.resolver` の素の鎖読みだった。`buildReceivedIssuerTrust` が常に own プロパティとして
  // 載せるため実運用では到達しないが、規律が片側だけだと後続の変更で非対称が固定化する。
  it('resolver を own プロパティに持たない trust は、汚染値を掴まず 3010 で倒れる', async () => {
    const trust = {
      issuerTrustAnchors: undefined,
      jwtVcIssuerMetadataResolution: undefined,
      jwtVcIssuerMetadataFetchImpl: undefined,
    } as unknown as ReceivedIssuerTrust;
    let polluted = false;

    await withPollutedPrototypeAsync(
      {
        resolver: {
          resolve: async () => {
            polluted = true;
            return undefined;
          },
        },
      },
      async () => {
        await expect(verifyReceivedCredential(trust, jwtReceived())).rejects.toThrow(
          new VericertsError(ErrorCodes.SIG_INVALID, {
            context: { reason: 'issuer_key_unresolved' },
          }),
        );
      },
    );

    expect(polluted).toBe(false);
  });
});
