/**
 * 取り込んだ秘密鍵（JWK、RFC 7517）から JWS 署名鍵を作る。
 *
 * 既存 DID（did:web / did:ethr / did:key の Ed25519 など）を取り込むとき、ユーザーはその DID の秘密鍵を
 * JWK（`d` を含む）で渡す。秘密鍵は SDK が保存せず、呼び出し側（拡張の暗号化ストア）が保持する。本関数は
 * JWK の検証と、既存の `createPrivateKeySigner` による署名鍵の構築だけを行う。
 *
 * 対応: `EC` / `P-256`（ES256）、`EC` / `secp256k1`（ES256K、RFC 8812）、`OKP` / `Ed25519`（EdDSA、RFC 8037）。
 *
 * セキュリティ上の注意: 秘密鍵・JWK を例外へ含めない。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CredentialAlg, CredentialSignerAlg } from '../vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../vc/signer.js';
import { algForPublicKeyJwk, samePublicKeyJwk } from './public-key-jwk.js';

/** 秘密鍵 JWK（RFC 7517 / 7518 §6 / 8037）。`d` が秘密鍵。 */
export type PrivateKeyJwk = Readonly<Record<string, unknown>>;

/** 秘密鍵 JWK を検証し、鍵種の `alg`・32 バイトの秘密鍵・公開鍵の形（`kty` / `crv`）を取り出す。 */
function parsePrivateKeyJwk(privateKeyJwk: PrivateKeyJwk) {
  const d = ownProperty<unknown>(privateKeyJwk, 'd');
  const publicShape: PublicKeyJwk = {
    kty: ownProperty<unknown>(privateKeyJwk, 'kty'),
    crv: ownProperty<unknown>(privateKeyJwk, 'crv'),
  };
  const alg = algForPublicKeyJwk(publicShape);
  if (typeof d !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  let privateKey: Uint8Array;
  try {
    privateKey = base64urlnopad.decode(d.replace(/=+$/, ''));
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  if (privateKey.length !== 32) {
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  return { alg, privateKey, publicShape };
}

/** 署名鍵を作り、JWK の `x` / `y` が `d` から導出した公開鍵と一致することを確かめ、`kid` を付ける。 */
function buildSigner<A extends CredentialSignerAlg>(
  privateKeyJwk: PrivateKeyJwk,
  parsed: ReturnType<typeof parsePrivateKeyJwk>,
  alg: A,
  kid: string | undefined,
): CredentialSigner<A> {
  let signer: CredentialSigner<A>;
  try {
    signer = createPrivateKeySigner(parsed.privateKey, alg);
  } catch {
    // 範囲外のスカラー等。noble の例外は秘密を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  const x = ownProperty<unknown>(privateKeyJwk, 'x');
  if (
    x !== undefined &&
    !samePublicKeyJwk(signer.publicKeyJwk, {
      ...parsed.publicShape,
      x,
      y: ownProperty<unknown>(privateKeyJwk, 'y'),
    })
  ) {
    // OKP は `y` を持たない。`samePublicKeyJwk` は `y` 欠落同士を一致とみなす。
    throw new VericertsError(ErrorCodes.INVALID_PRIVATE_KEY);
  }
  return kid === undefined ? signer : { ...signer, kid };
}

/**
 * 秘密鍵 JWK から署名鍵を構築する（IANA 登録済みの `alg`: ES256 / ES256K / EdDSA）。
 *
 * JWK に `x`（`y`）が含まれる場合は、`d` から導出した公開鍵と一致することを確かめる（取り違え・改ざんの検出）。
 * `kid` 省略時は署名鍵に `kid` を付けない。
 *
 * @param privateKeyJwk 秘密鍵 JWK（`kty` / `crv` / `d` 必須）。
 * @param kid JWS ヘッダへ載せる検証メソッドの DID URL。
 * @returns `alg` / `publicKeyJwk` / `kid` / `sign` を持つ署名鍵。
 * @throws JWK が不正・`d` が 32 バイトでない・`x` / `y` が `d` と一致しない場合（VericertsError、code `1003`）、
 *         未対応の鍵種の場合（code `1030`）。
 */
export function createExternalKeySigner(
  privateKeyJwk: PrivateKeyJwk,
  kid?: string,
): CredentialSigner<CredentialAlg> {
  const parsed = parsePrivateKeyJwk(privateKeyJwk);
  return buildSigner(privateKeyJwk, parsed, parsed.alg, kid);
}

/**
 * secp256k1 の秘密鍵 JWK から `alg: "ES256K-R"` の署名鍵を構築する（EIP-191 の recoverable 署名。IANA 登録外の標準外の
 * 例外、did:pkh / did:ethr の controller 鍵用）。JWK の検証は {@link createExternalKeySigner} と同じ。
 *
 * @throws secp256k1 以外の鍵（code `1030`）、JWK が不正（code `1003`）。
 */
export function createExternalEip191Signer(
  privateKeyJwk: PrivateKeyJwk,
  kid?: string,
): CredentialSigner<CredentialSignerAlg> {
  const parsed = parsePrivateKeyJwk(privateKeyJwk);
  if (parsed.alg !== 'ES256K') {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  return buildSigner(privateKeyJwk, parsed, 'ES256K-R', kid);
}
