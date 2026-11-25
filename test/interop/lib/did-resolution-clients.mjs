// test/interop/lib/did-resolution-clients.mjs
//
// run-did-resolution-matrix.mjs が実ピアへ DID 解決を要求する HTTP クライアント。
// 経路は DIF DID Resolution HTTPS Binding（`GET <baseUrl><resolvePath><did>`）で、
// didkit-http の `GET /identifiers/{did}` と当方アダプタの同形エンドポイントを同じ関数で叩く。
//
// fail-closed の方針: 「解決できた」と見なすのは、
// 2xx・JSON オブジェクト・解決メタデータにエラー無し・`id` が要求した DID と一致・
// 署名検証に使える鍵が 1 件以上取り出せる、をすべて満たした応答だけ。さらに DID 自体に公開鍵が
// 埋まっているメソッド（did:key / did:jwk）は、`findVerificationMethodWithKey` で**その鍵と
// 一致すること**まで要求する（`id` だけ合っていて無関係な鍵を返す解決器を通さない）。
// ピア未起動・タイムアウト・5xx の HTML・空の DID Document を「解決できた」と誤認すると、Nightly が
// 実質何も検証しないまま緑になる。例外も throw せず `{ resolved: false, error }` に倒し、呼び出し側が
// pass にできない形で返す。

/** 解決 1 回あたりの既定タイムアウト。ピア未起動時に Nightly が無期限に待たないようにする。 */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * DIF DID Resolution HTTPS Binding の Resolution Result を要求する既定の Accept ヘッダ。
 *
 * ピアが `resolveAccept` を持つ場合はそちらを優先する（`pairs.json` の
 * `didResolution.peers.<name>.resolveAccept`）。DIF Binding は Accept で「Resolution Result」と
 * 「DID Document 表現」のどちらを返すかを選ぶ規定だが、実装の content negotiation の質はまちまちで、
 * この既定値では規定どおりの Resolution Result を返さないピアがある（didkit-http）。
 * 既定値を緩めるのではなくピア単位で上書きするのは、**規定どおり返せるピアには規定どおり要求し続ける**
 * ため — 全ピアを DID Document 表現に倒すと、`didResolutionMetadata.error` を見る検査が
 * どのピアに対しても働かなくなる。
 */
const DEFAULT_RESOLUTION_ACCEPT = 'application/ld+json;profile="https://w3id.org/did-resolution"';

/** 理由欄に載せる応答本文の抜粋（HTML の全文などでレポートを埋めない）。 */
function excerpt(text) {
  return String(text).replace(/\s+/g, ' ').slice(0, 200);
}

/**
 * 通信失敗の実際の原因を理由欄に出す。
 *
 * undici は接続失敗を `TypeError: fetch failed` に包み、ECONNREFUSED 等は `cause` にしか残らない。
 * さらに localhost は IPv4/IPv6 の両方を試すため `cause` が message 空の AggregateError になる
 * （個々の原因は `code` / `errors` 側）。原因が出ないとピア未起動と DNS 失敗を切り分けられない。
 */
function describeCause(cause) {
  if (!cause) return '';
  const detail =
    cause.message ||
    cause.code ||
    (Array.isArray(cause.errors) ? cause.errors.map((e) => e?.code ?? e?.message).join(', ') : '');
  return detail ? ` / cause: ${detail}` : '';
}

/**
 * 通信そのものが失敗したときの理由文字列。
 * タイムアウト（AbortSignal.timeout の TimeoutError / AbortError）と、それ以外の接続失敗
 * （ECONNREFUSED 等のピア未起動）を語で区別できるようにする。どちらも「ピアが応答しなかった」で
 * 一括りにすると、Nightly の失敗から原因（未起動 / 遅延）を切り分けられない。
 */
function describeFetchFailure(error, url) {
  const name = error?.name ?? 'Error';
  const message = error?.message ?? String(error);
  if (name === 'TimeoutError' || name === 'AbortError') {
    return `resolve-timeout: ${url} が制限時間内に応答しなかった (${name}: ${message})`;
  }
  return `resolve-connect-error: ${url} へ接続できなかった (${name}: ${message}${describeCause(error?.cause)})`;
}

/**
 * DID Document から署名検証に使える鍵を取り出せるかを調べる。
 *
 * `id` が一致するだけの空の DID Document を返しても
 * pass にしないため、`verificationMethod` が 1 件以上
 * あり、各要素が `id` / `type` と鍵マテリアルを持つことまで見る。**鍵が「正しい」かどうかは
 * ここでは見ない**（表現が 3 通りあり、ここは全メソッド共通の層のため）。要求した DID の鍵かの
 * 照合は `findVerificationMethodWithKey` が fixture の `expectedKey` と突き合わせて行う。
 *
 * 鍵マテリアルの表現はピアの解決器で異なり、同じ did:key でも `publicKeyJwk`（didkit / ssi）・
 * `publicKeyMultibase`（Ed25519VerificationKey2020 系）・`publicKeyBase58`
 * （Ed25519VerificationKey2018 系。`key-did-resolver` がこの形で返す）のいずれにもなる。
 * ここは「検証鍵が取り出せるか」だけを見る層なので 3 つとも受理する — 1 つに絞ると、鍵を
 * 正しく返しているピアを表現の違いだけで fail にしてしまう（本物の非互換を埋もれさせる）。
 *
 * @returns 問題があればその理由、無ければ undefined。
 */
function describeVerificationMethodProblem(didDocument) {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    return 'verification-method-missing: DID Document に verificationMethod が無く、検証鍵を取り出せない';
  }
  for (const [index, method] of methods.entries()) {
    const at = `verificationMethod[${index}]`;
    if (method === null || typeof method !== 'object' || Array.isArray(method)) {
      return `verification-method-invalid: ${at} がオブジェクトではない`;
    }
    if (typeof method.id !== 'string' || typeof method.type !== 'string') {
      return `verification-method-invalid: ${at} に文字列の id / type が無い`;
    }
    const jwk = method.publicKeyJwk;
    const hasJwk = jwk !== null && typeof jwk === 'object' && !Array.isArray(jwk);
    const hasEncodedKey =
      typeof method.publicKeyMultibase === 'string' || typeof method.publicKeyBase58 === 'string';
    if (!hasJwk && !hasEncodedKey) {
      return `verification-method-invalid: ${at} (${method.id}) に publicKeyJwk / publicKeyMultibase / publicKeyBase58 のいずれも無い`;
    }
  }
  return undefined;
}

/** 期待鍵と突き合わせる、符号化された鍵マテリアルのメンバ（JWK は構造が違うので別扱い）。 */
const ENCODED_KEY_MEMBERS = ['publicKeyMultibase', 'publicKeyBase58'];

/**
 * 期待 JWK と一致するか。ピアが `kid` / `alg` / `use` を足して返すことがあるため、期待値の各メンバが
 * 一致することだけを見る（完全一致は求めない）。
 *
 * **期待値のメンバが 0 件（`{}`）なら一致と見なさない**: `every` は空集合で真になるため、そのままだと
 * `publicKeyJwk` を持つ任意の検証鍵が一致扱いになり、fixture の `expectedKey` が壊れた瞬間に
 * 鍵の照合が fail-open へ戻る。
 */
function matchesExpectedJwk(jwk, expectedJwk) {
  if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) return false;
  const expectedMembers = Object.entries(expectedJwk);
  if (expectedMembers.length === 0) return false;
  return expectedMembers.every(([member, value]) => jwk[member] === value);
}

/**
 * fixture の期待公開鍵と一致する検証鍵を DID Document から探す。
 *
 * did:key / did:jwk のように **DID 自体が公開鍵を含む**メソッドでは、解決結果が「要求した DID の鍵」を
 * 返したことまで確かめられる。これが無いと `id` だけ合っていて無関係な鍵を返す解決器が pass し、
 * 解決器の返した鍵が不正でも検出できない。
 *
 * 鍵マテリアルの表現はピアの解決器で異なる（`key-did-resolver` は `Ed25519VerificationKey2018` +
 * `publicKeyBase58`、didkit / ssi は `publicKeyJwk`、`Ed25519VerificationKey2020` 系は
 * `publicKeyMultibase`）ため、`expectedKey` は did:key の method-specific id から導いた同じ鍵の
 * 3 表現を持ち、**相手が返した表現に対応する期待値**と突き合わせる（`pairs.json` の
 * `didResolution.fixtures.<method>.expectedKey`）。どの表現でも突き合わせられない検証鍵は
 * 一致と見なさない（照合できないものを通さない）。
 *
 * @returns 一致した verificationMethod。無ければ undefined。
 */
export function findVerificationMethodWithKey(didDocument, expectedKey) {
  const methods = Array.isArray(didDocument?.verificationMethod)
    ? didDocument.verificationMethod
    : [];
  return methods.find((method) => {
    if (
      expectedKey.publicKeyJwk &&
      matchesExpectedJwk(method?.publicKeyJwk, expectedKey.publicKeyJwk)
    ) {
      return true;
    }
    return ENCODED_KEY_MEMBERS.some(
      (member) =>
        typeof expectedKey[member] === 'string' && method?.[member] === expectedKey[member],
    );
  });
}

/**
 * ピアに DID を 1 件解決させる。
 *
 * @param fetchImpl `fetch` 互換（テストでは差し替える）。
 * @param peer `pairs.json` の `didResolution.peers.<name>`（`baseUrl` / `resolvePath` と、
 *   あれば Accept ヘッダの上書き `resolveAccept` を使う）。
 * @param did 解決対象の DID。
 * @returns `{ resolved: true, didDocument }` または `{ resolved: false, error }`。例外は投げない。
 */
export async function resolveDidWithPeer(fetchImpl, peer, did, { timeoutMs } = {}) {
  const url = `${peer.baseUrl}${peer.resolvePath}${encodeURIComponent(did)}`;
  let response;
  let text;
  try {
    response = await fetchImpl(url, {
      headers: { accept: peer.resolveAccept ?? DEFAULT_RESOLUTION_ACCEPT },
      signal: AbortSignal.timeout(timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    text = await response.text();
  } catch (error) {
    return { resolved: false, error: describeFetchFailure(error, url) };
  }

  if (!response.ok) {
    return { resolved: false, error: `HTTP ${response.status}: ${excerpt(text)}` };
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    // 5xx のプロキシ HTML・プレーンテキストのエラーを「解決できた」と見なさない。
    return { resolved: false, error: `JSON 以外の応答を返した: ${excerpt(text)}` };
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { resolved: false, error: `JSON オブジェクト以外の応答を返した: ${excerpt(text)}` };
  }

  const metadataError = body.didResolutionMetadata?.error;
  if (metadataError !== undefined && metadataError !== null) {
    const detail =
      typeof metadataError === 'string' ? metadataError : JSON.stringify(metadataError);
    return { resolved: false, error: `didResolutionMetadata.error: ${detail}` };
  }

  // DIF HTTPS Binding の応答は Accept 次第で「DID Resolution Result（didDocument を内包）」と
  // 「DID Document 単体」の両方があり得る（ピアによって既定も異なる）。どちらで来ても同じ検査に
  // かけるため、`didDocument` キーの有無で取り出し方を分ける。
  const didDocument = 'didDocument' in body ? body.didDocument : body;
  if (didDocument === null || typeof didDocument !== 'object' || Array.isArray(didDocument)) {
    return { resolved: false, error: `応答から DID Document を取り出せなかった: ${excerpt(text)}` };
  }
  if (didDocument.id !== did) {
    return {
      resolved: false,
      error: `did-mismatch: 要求した DID (${did}) と解決結果の id (${JSON.stringify(didDocument.id)}) が一致しない`,
    };
  }
  const problem = describeVerificationMethodProblem(didDocument);
  if (problem !== undefined) {
    return { resolved: false, error: problem };
  }
  return { resolved: true, didDocument };
}
