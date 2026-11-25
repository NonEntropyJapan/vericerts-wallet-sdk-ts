/**
 * `Wallet.receiveCredential`テスト用の共有フィクスチャ。
 *
 * OID4VCI フロー配線のテスト（`wallet.receive-credential.test.ts`）と、受領した VC の既定署名検証
 * のテスト（`wallet.receive-credential.default-verify.test.ts` /
 * `wallet.receive-credential.verify-received-di.test.ts`）の両方から使う共通部分だけをここへ集める
 * （Linterly の 300 行/ファイル上限。ファイル分割時の重複を避ける）。
 *
 * 実鍵素材のみを使い（モック署名器は使わない）、SD-JWT VC / JWT-VC の署名は実際に計算される。
 */

import {
  CONFIGURATION_ID,
  CREDENTIAL_URL,
  createStubFetch,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  TOKEN_URL,
  tokenResponse,
} from '../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import {
  createPrivateKeySigner,
  createSdJwt,
  issueCredential,
  VC_V2_CONTEXT,
} from '../../../internal/credential/index.js';
import { signCompactJws } from '../../../internal/credential/vc/compact-jws.js';
import { createDidKey } from '../../../internal/identity/method-key.js';
import { getSecp256k1PublicKey } from '../../../internal/keymanager/signer.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import type { Wallet } from '../../types.js';

export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** import + ペルソナ作成・アクティブ化済みの Wallet を用意する。 */
export async function setupWallet(): Promise<Wallet> {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  return wallet;
}

/** Issuer（did:key）の決定論的な secp256k1 秘密鍵。実署名に使う（モック署名器は使わない）。 */
export const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(11);

/** 上記秘密鍵から導いた did:key の DID。`createWallet` の Resolver で解決できる Issuer。 */
export const ISSUER_DID_KEY = createDidKey(
  'secp256k1',
  getSecp256k1PublicKey(ISSUER_PRIVATE_KEY, true),
).id;

/**
 * JWK を持たない Issuer 鍵の代表（did:pkh は `blockchainAccountId` のみを持つ）。
 * EIP-55 チェックサムは検証されないため `0x` + 40 hex であれば解決できる。
 */
export const ISSUER_DID_PKH = 'did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb';

/**
 * 未登録 DID メソッド。Resolver が未対応メソッドとして投げるため Issuer 鍵が解決できない。
 * ネットワーク断・did:web 到達不可も既定検証では同じ `issuer_key_unresolved` へ正規化されるため、
 * 「鍵が手に入らない DID 解決失敗」全般の代表としてこの DID を使う。
 */
export const UNRESOLVABLE_ISSUER_DID = 'did:example:unregistered-method-test-670';

/** 指定した Issuer DID を `iss` に持つ SD-JWT VC を実署名で組み立てる。 */
export function buildIssuedSdJwt(issuerDid: string): string {
  // 署名鍵は常に `ISSUER_PRIVATE_KEY`。did:pkh / 未対応メソッドのケースは鍵解決の段で失敗するため、
  // 署名鍵が DID と対応している必要はない。
  return createSdJwt(createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256K'), {
    vct: CONFIGURATION_ID,
    disclosureClaims: ['degree'],
    claims: { degree: 'Laurea' },
    issuer: issuerDid,
  });
}

/**
 * 指定した Issuer DID を `issuer` に持つ JWT-VC（W3C VC JWS。`~` を含まない素の JWT）を
 * 実署名で組み立てる。SD-JWT VC 用の `buildIssuedSdJwt` と対になる、`format: 'jwt'` 分岐用。
 */
export function buildIssuedJwtVc(issuerDid: string): string {
  return issueCredential(
    {
      '@context': [VC_V2_CONTEXT],
      type: ['VerifiableCredential', CONFIGURATION_ID],
      issuer: issuerDid,
      credentialSubject: { id: 'did:example:holder-670', degree: 'Laurea' },
      issuanceDate: new Date().toISOString(),
    },
    createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256K'),
  );
}

/**
 * `buildIssuedJwtVc` と同じ内容を、walt.id が VC 2.0 の `@context` に対して出す表現（`vc` で包まず
 * payload 自体が VC 本体。`issuanceDate` / `expirationDate` は `validFrom` / `validUntil`）
 * の JWT-VC として実署名で組み立てる。claim のキーは walt.id の実 payload に揃える。
 */
export function buildIssuedFlatJwtVc(issuerDid: string): string {
  const signer = createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256K');
  const nowSeconds = Math.floor(Date.now() / 1000);
  const subject = 'did:example:holder-670';
  const id = 'urn:uuid:3925-flat';
  const header = Buffer.from(JSON.stringify({ alg: 'ES256K', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuerDid,
      sub: subject,
      '@context': [VC_V2_CONTEXT],
      id,
      type: ['VerifiableCredential', CONFIGURATION_ID],
      issuer: issuerDid,
      credentialSubject: { id: subject, degree: 'Laurea' },
      validFrom: new Date(nowSeconds * 1000).toISOString(),
      validUntil: new Date((nowSeconds + 86_400) * 1000).toISOString(),
      jti: id,
      exp: nowSeconds + 86_400,
      iat: nowSeconds,
      nbf: nowSeconds,
    }),
  ).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** Credential Endpoint が指定の VC（SD-JWT または JWT-VC）をそのまま返す pre-authorized_code の stub。 */
export function credentialStub(raw: string): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: () => json({ credential: raw }),
  });
}

/**
 * 署名は正しいが envelope と body が食い違う JWT-VC（`sub` ≠ `vc.credentialSubject.id`）。
 * 検証は署名の確定後に `3002`（`VC_SCHEMA_INVALID`）で落ちる = 「署名が合わない」ではない失敗の代表。
 */
export function buildIssuedJwtVcWithEnvelopeMismatch(issuerDid: string): string {
  const issuedAtSeconds = Math.floor(Date.now() / 1000);
  return signCompactJws(
    { alg: 'ES256K', typ: 'JWT' },
    {
      iss: issuerDid,
      sub: 'did:example:someone-else-3927',
      nbf: issuedAtSeconds,
      iat: issuedAtSeconds,
      vc: {
        '@context': [VC_V2_CONTEXT],
        type: ['VerifiableCredential', CONFIGURATION_ID],
        issuer: issuerDid,
        credentialSubject: { id: 'did:example:holder-3927', degree: 'Laurea' },
        issuanceDate: new Date(issuedAtSeconds * 1000).toISOString(),
      },
    },
    createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256K'),
  );
}

/**
 * Issuer-signed JWT の署名セグメントを 1 文字書き換える。SD-JWT VC（`~` 区切り）・JWT-VC（`~` を
 * 含まない素の JWT）のどちらの `raw` を渡しても、先頭の JWT（Issuer-signed 部分）だけを改竄する。
 * 先頭文字を変えるのは、末尾文字だと余剰ビットしか動かず復号後の署名バイトが変わらないため。
 */
export function tamperIssuerSignature(raw: string): string {
  const [issuerJwt, ...disclosures] = raw.split('~');
  const segments = (issuerJwt as string).split('.');
  const signature = segments[2] as string;
  segments[2] = `${signature.startsWith('A') ? 'B' : 'A'}${signature.slice(1)}`;
  return [segments.join('.'), ...disclosures].join('~');
}
