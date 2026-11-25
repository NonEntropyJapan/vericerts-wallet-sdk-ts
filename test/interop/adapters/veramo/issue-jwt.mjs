// test/interop/adapters/veramo/issue-jwt.mjs
//
// Veramo アダプタの JWT-VC 発行部分（`server.mjs` から `/vc/issue` が呼ぶ）。agent を引数で受けるため、
// Veramo を起動せずに（スタブ agent で）呼び出し引数を単体テストできる。
//
// JWS ヘッダへ `kid`（発行者鍵の DID URL）を載せる。didkit-http（ssi crate）は JWT-VC の検証鍵を
// ヘッダの `kid` からのみ解決し、`kid` が無いと `missing public key`（HTTP 400）で拒否する。
// Veramo（did-jwt-vc）は既定で `kid` を出さない（VCDM 1.1 §6.3.1 では `kid` は MAY）。

/**
 * `did:key` の検証メソッド DID URL（`did:key:Z#Z`）を返す。
 *
 * did:key の検証メソッド ID のフラグメントは、メソッド固有 ID（`z...`）と同一である。
 *
 * @param did `did:key:z...` 形式の DID。
 * @returns `did:key:z...#z...`。
 * @throws `did:key:` 形式でない場合。
 */
export function didKeyVerificationMethod(did) {
  const prefix = 'did:key:';
  if (!did.startsWith(prefix)) {
    throw new Error(`expected a did:key DID: ${did}`);
  }
  return `${did}#${did.slice(prefix.length)}`;
}

/**
 * Veramo agent で JWT-VC を 1 通発行する（JWS ヘッダに `kid` を載せる）。
 *
 * @param agent `createVerifiableCredential` を持つ Veramo agent。
 * @param identifier 発行者の管理 DID（`did` を持つ）。
 * @param subject `credentialSubject` へ展開する追加クレーム。
 * @returns コンパクト形式の JWT-VC。
 */
export async function issueJwtVc(agent, identifier, subject) {
  const vc = await agent.createVerifiableCredential({
    credential: {
      issuer: { id: identifier.did },
      credentialSubject: { id: identifier.did, ...subject },
    },
    proofFormat: 'jwt',
    header: { kid: didKeyVerificationMethod(identifier.did) },
  });
  return vc.proof.jwt;
}
