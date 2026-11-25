/**
 * JWT-VC の JWS ヘッダ `kid` を、発行者 DID が `did:key` のときに自動で決める。
 *
 * `kid`（JWS Header の鍵識別子）は VCDM 1.1 §6.3.1 / RFC 7515 §4.1.4 で任意（MAY）だが、検証側が
 * `kid`（DID URL）からしか検証鍵を解決しない実装（例: didkit-http / ssi crate は `iss` や `jwk` に
 * フォールバックせず、`kid` が無いと `missing public key` で拒否する）がある。`kid` は署名の
 * 対象外の鍵ヒントを載せるだけなので、載せても標準仕様の範囲内であり、`kid` を使わない検証側には影響しない。
 *
 * 自動付与は **発行者が `did:key` で、その DID が表す公開鍵が署名鍵と一致するとき**に限る。
 * `did:key` の DID Document は DID 文字列だけから決まる（解決のための I/O が要らない）ので、同期で
 * 判定でき、署名鍵と一致しない DID の `kid`（検証側が別の鍵を引く原因になる）は付かない。
 * それ以外の発行者（`did:web` / `did:ethr` など）は DID Document を解決しないと検証メソッド id を
 * 決められないため自動では付けない（呼び出し側が `signer.kid` を指定する従来どおりの経路）。
 *
 * 明示した `signer.kid` は常に優先する。
 */

import { VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { verificationMethodsOf } from '../../identity/did-document-read.js';
import { resolveDidKey } from '../../identity/method-key.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { samePublicKeyJwk } from '../did-signing/public-key-jwk.js';
import type { CredentialSignerAlg } from './jws.js';
import type { JwsHeaderSource } from './signer.js';
import { verificationMethodToJwk } from './verifier-key-jwk.js';

const DID_KEY_PREFIX = 'did:key:';

/** `kid` を決めるのに必要な署名鍵の最小の形（`CredentialSigner` / `AsyncCredentialSigner` が満たす）。 */
interface KidSignerSource extends JwsHeaderSource<CredentialSignerAlg> {
  readonly publicKeyJwk: PublicKeyJwk;
}

/**
 * `issuer` が署名鍵自身の `did:key` なら、その検証メソッド id（`did:key:Z#Z`）を返す。
 *
 * @param issuer `vc.issuer`。
 * @param publicKeyJwk 署名鍵の公開鍵 JWK。
 * @returns 検証メソッド id。`did:key` でない・鍵が一致しない・解決できない場合は `undefined`。
 */
function didKeyKidFor(issuer: string, publicKeyJwk: PublicKeyJwk): string | undefined {
  if (!issuer.startsWith(DID_KEY_PREFIX)) {
    return undefined;
  }
  try {
    const [method] = verificationMethodsOf(resolveDidKey(issuer));
    if (method === undefined || !samePublicKeyJwk(verificationMethodToJwk(method), publicKeyJwk)) {
      return undefined;
    }
    return ownProperty<string>(method, 'id');
  } catch (error) {
    // 不正な `did:key`（2001）や JWK に直せない鍵（2010）は `kid` を付けないだけで、発行は止めない。
    // `kid` は任意の鍵ヒントであり、付けられないことを理由に VC の発行を失敗させない。
    if (error instanceof VericertsError) {
      return undefined;
    }
    throw error;
  }
}

/**
 * JWS ヘッダを組み立てる素（`buildJwsHeader` の第 1 引数）を返す。
 *
 * - `signer` が自身のプロパティとして `kid` を持つ（明示指定）→ `signer` をそのまま返す。
 * - 発行者が署名鍵自身の `did:key` → `{ alg, kid: 'did:key:Z#Z' }`。
 * - それ以外 → `signer` をそのまま返す（`kid` は出力されない。従来どおり）。
 *
 * `kid` の有無は `Object.hasOwn` で判定する（`buildJwsHeader` と同じ理由。プロトタイプ汚染された
 * `kid` を「明示指定」と誤認しない）。
 *
 * @param issuer `vc.issuer`（`string` であることは呼び出し側が確認済み）。
 * @param signer JWT-VC 署名鍵。
 * @returns `buildJwsHeader` に渡す素。
 */
export function headerSourceWithDidKeyKid(
  issuer: string,
  signer: KidSignerSource,
): JwsHeaderSource<CredentialSignerAlg> {
  if (Object.hasOwn(signer, 'kid') && signer.kid !== undefined) {
    return signer;
  }
  const kid = didKeyKidFor(issuer, signer.publicKeyJwk);
  return kid === undefined ? signer : { alg: signer.alg, kid };
}
