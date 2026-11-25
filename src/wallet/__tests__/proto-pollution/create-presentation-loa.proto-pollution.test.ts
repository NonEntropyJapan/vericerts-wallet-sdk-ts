/**
 * `Wallet.createPresentation` の LoA 判定フック（`wallet/credential/create-presentation.ts` の
 * `buildLoaCheck`）が `Object.prototype` 汚染下でも own-property 規律を守ることの
 * 回帰テスト。
 *
 * `request.requiredLoA` を鎖読みすると、`required_loa` を告知していない要求でも
 * `Object.prototype.requiredLoA` の汚染値が「Verifier が要求した LoA」として扱われ、
 * 汚染値次第で本来発火しないはずの `LOA_MISMATCH`（10030）が発火する（誤った拒否）か、
 * 逆に本来必要な判定が意図しない LoA 値にすり替わる（fail-open / fail-closed どちらの方向にも
 * ぶれ得る不安定な挙動）。own 限定で読み、告知の無い要求では判定自体をスキップする（従来どおり
 * `checkLoa` が no-op のまま）ことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import type { VerifiableCredential } from '../../../internal/credential/index.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

/** `required_loa` を告知しない直接形式の requestURI（VC の `evidence` は無しでも候補になる要求）。 */
function buildRequestUriWithoutRequiredLoa(): string {
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

/** evidence を持たない VC（`verifyEvidence` は low 要求のみ充足する）。 */
function makeVcWithoutEvidence(id: string, name: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

async function setupWallet(): Promise<Wallet> {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return wallet;
}

describe('Wallet.createPresentation — LoA 判定フックの Object.prototype 汚染耐性', () => {
  it('required_loa を告知していない要求は、Object.prototype.requiredLoA 汚染下でも LOA_MISMATCH を発火しない', async () => {
    const wallet = await setupWallet();
    // evidence を持たない VC（substantial/high を要求されれば不足するはずの VC）。
    await wallet.storeCredential(makeVcWithoutEvidence('urn:vc:bob', 'Bob'));

    // `Object.prototype.requiredLoA = 'high'` を汚染した状態で提示を作る。要求は `required_loa` を
    // 告知していない（own プロパティを持たない）ため、鎖読みなら汚染値 `high` が「要求 LoA」として
    // 採用され、evidence の無い VC は不足判定されて誤って LOA_MISMATCH が発火する。own 限定読みなら
    // 判定自体がスキップされ、従来どおり VP 作成が成功する。
    const result = await withPollutedPrototypeAsync({ requiredLoA: 'high' }, () =>
      wallet.createPresentation(buildRequestUriWithoutRequiredLoa(), ['urn:vc:bob']),
    );

    expect(result.verifiableCredential).toHaveLength(1);
  });
});
