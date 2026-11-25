/**
 * `did_signMessage` の署名・検証（RFC 7515 + RFC 7797 の detached コンパクト JWS）。
 *
 * 出力形式（固定）: `base64url(header)..base64url(signature)`（payload セグメントは空。detached content、
 * RFC 7515 Appendix F / RFC 7797 §5.2）。
 * - header: `{ "alg": <ES256|ES256K|EdDSA>, "kid": <署名した検証メソッドの DID URL>, "b64": false, "crit": ["b64"] }`
 *   （`typ` は付けない）。
 * - payload: メッセージそのもの（UTF-8 バイト列。独自プレフィックスや長さは付けない）。RFC 7797 の Unencoded
 *   Payload Option（`b64: false`）なので signing-input は `ASCII(base64url(header)) || '.' || payload` で、
 *   payload は base64url 化しない。detached なので `.` や任意の文字を含むメッセージもそのまま扱える
 *   （dApp はメッセージを既に持っており、検証側へ渡す）。
 * - signature: signing-input への署名。ES256 / ES256K は SHA-256 に対する ECDSA の `r || s`（64 バイト）、
 *   EdDSA は signing-input そのものへの Ed25519。
 *
 * 偽造対策: DID 署名鍵は VC-JWT / VP-JWT / SIOPv2 id_token / proof JWT の署名にも使われる。dApp が
 * JWT の signing-input 形の文字列を渡して得た署名が、そのまま有効な JWT の署名になってはならない。ここでは独自の
 * ドメイン分離プレフィックスを使わず、標準の `crit`（RFC 7515 §4.1.11）で防ぐ。`crit: ["b64"]` を理解しない
 * JWS 検証器は JWS 全体を拒否しなければならない（MUST）ので、通常の JWT / JWS 検証器はこの署名を JWT として
 * 受理しない。本 SDK の検証経路は `crit` を持つヘッダをすべて拒否する（`assertNoCriticalHeaders`）。
 *
 * 検証（{@link verifyMessageJws}）は `crit` がちょうど `["b64"]`・`b64` が `false` のヘッダだけを受理し、
 * `kid` の DID を解決して、`kid` の検証メソッドが DID Document の `authentication` に列挙されていることを確かめてから、
 * 呼び出し側が渡したメッセージに対する署名を検証する（鍵は DID Document から引き、JWS 側の鍵情報は信用しない）。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DidResolverLike } from '../../identity/bounded-resolver.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { assertAlg, type CredentialSignerAlg } from '../vc/jws.js';
import type { AnyCredentialSigner } from '../vc/signer.js';
import { verifyWithMethod } from '../vc/verifier-key.js';
import { inlineExternalMethods } from './external-methods.js';
import { methodsInRelationship } from './key-binding.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/** 検証済みの署名メッセージ（メッセージ本体は呼び出し側が検証器へ渡したもの）。 */
export interface VerifiedSignedMessage {
  /** 署名者の DID。 */
  readonly did: string;
  /** 署名した検証メソッドの DID URL（JWS `kid`）。 */
  readonly kid: string;
  /** JWS `alg`。 */
  readonly alg: CredentialSignerAlg;
}

/** `verifyMessageJws` のオプション。 */
export interface VerifyMessageOptions {
  /** 署名されているはずのメッセージ（detached content。JWS には含まれないので呼び出し側が渡す）。 */
  readonly message: string;
  /** DID Resolver。`kid` の DID を毎回解決する（キャッシュしない）。 */
  readonly resolver: DidResolverLike;
  /**
   * 署名者として期待する DID。指定すると、その DID の DID Document の `authentication` が `kid` を列挙している JWS だけを
   * 受理し、結果の `did` はこの DID になる。`kid` が別 DID の検証メソッド（委任元ペルソナの `did:key#…` など）でも、
   * 期待する DID（委任先）が `authentication` で列挙（埋め込み・DID URL 参照）していれば受理する（DID Core §5.3）。
   * 列挙していなければ `3010`（`did_mismatch`）。
   */
  readonly expectedDid?: string;
}

/** 署名・検証の失敗（`3010`）。`reason` は固定識別子のみ。 */
function invalid(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.SIG_INVALID, { context: { reason } });
}

/** `crit` がちょうど `["b64"]` か（RFC 7797 §6: `b64` を使うとき `crit` に載せなければならない）。 */
function isCritB64Only(crit: unknown): boolean {
  return Array.isArray(crit) && crit.length === 1 && crit[0] === 'b64';
}

/** JWS signing-input（RFC 7797 §3: `ASCII(BASE64URL(header)) || '.' || payload`。payload は無加工のバイト列）。 */
function signingInputOf(headerSegment: string, message: string): Uint8Array {
  const head = encoder.encode(`${headerSegment}.`);
  const body = encoder.encode(message);
  const input = new Uint8Array(head.length + body.length);
  input.set(head);
  input.set(body, head.length);
  return input;
}

/**
 * メッセージを detached コンパクト JWS（RFC 7515 + RFC 7797）に署名する。
 *
 * @param message 署名するメッセージ（UTF-8 文字列。JWS payload のバイト列としてそのまま署名する）。
 * @param signer `kid` 付きの署名鍵（`resolvePersonaSigner` の戻り値の `signer`）。
 * @returns `base64url(header)..base64url(signature)`（payload セグメントは空）。
 * @throws `signer.kid` が無い場合（VericertsError、code `2007`）。
 */
export async function signMessageJws(
  message: string,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
): Promise<string> {
  const kid = Object.hasOwn(signer, 'kid') ? signer.kid : undefined;
  if (kid === undefined) {
    throw new VericertsError(ErrorCodes.DID_SIGNING_KEY_UNAVAILABLE);
  }
  const header = base64urlnopad.encode(
    encoder.encode(JSON.stringify({ alg: signer.alg, kid, b64: false, crit: ['b64'] })),
  );
  const signature = await signer.sign(signingInputOf(header, message));
  return `${header}..${base64urlnopad.encode(signature)}`;
}

/**
 * `signMessageJws` が作った JWS を、呼び出し側が持つメッセージに対して検証する。
 *
 * 1. 構造（payload セグメントが空の 3 セグメント）・ヘッダ（`alg` が ES256 / ES256K / EdDSA、`crit` がちょうど
 *    `["b64"]`、`b64` が `false`）・`kid`（DID URL）を確かめる。`alg=none`・他の `crit` 要素・`b64: true`・
 *    attached payload は拒否する。
 * 2. 署名主体の DID（`expectedDid`、無ければ `kid` の DID）を解決し、`kid` の検証メソッドが `authentication` に
 *    列挙されていることを確かめる（他 DID の検証メソッドへの DID URL 参照は、その DID を解決して辿る）。
 * 3. その検証メソッドの公開鍵で、`message` から組み立てた signing-input への署名を検証する（`alg` と鍵種が合わなければ失敗）。
 *
 * @returns 検証済みの署名者・`kid`・`alg`。
 * @throws 構造不正・ヘッダ不正・署名不一致（メッセージ不一致を含む）・`expectedDid` 不一致（VericertsError、code `3010`）、
 *         `alg=none`（`3011`）、`kid` の検証メソッドが DID Document に無い・`authentication` に無い・失効（`2017`）、
 *         DID 解決の失敗（`2001` / `2002` / `2003`）・参照先の検証メソッドを辿れない（`2010`）。
 */
export async function verifyMessageJws(
  jws: string,
  opts: VerifyMessageOptions,
): Promise<VerifiedSignedMessage> {
  const message = ownProperty<unknown>(opts, 'message');
  if (typeof message !== 'string') {
    throw invalid('message_missing');
  }
  const parts = jws.split('.');
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  if (parts.length !== 3 || !headerSegment || !signatureSegment) {
    throw invalid('malformed');
  }
  if (payloadSegment !== '') {
    throw invalid('payload_attached');
  }
  let header: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = parseJsonWithoutPrototype(
      decoder.decode(base64urlnopad.decode(headerSegment)),
    ) as Record<string, unknown>;
    signature = base64urlnopad.decode(signatureSegment);
  } catch {
    throw invalid('malformed');
  }
  const alg = assertAlg(header, { allowEs256kR: true });
  if (!isCritB64Only(ownProperty<unknown>(header, 'crit'))) {
    throw invalid('crit');
  }
  if (ownProperty<unknown>(header, 'b64') !== false) {
    throw invalid('b64');
  }
  const kid = ownProperty<unknown>(header, 'kid');
  if (typeof kid !== 'string' || !kid.includes('#') || !kid.startsWith('did:')) {
    throw invalid('kid_missing');
  }
  const kidDid = kid.slice(0, kid.indexOf('#'));
  const expectedDid = ownProperty<string>(opts, 'expectedDid');
  // 署名主体: 既定は `kid` の DID。`expectedDid` が `kid` の DID と違うときは、検証側が「その DID として」の署名を
  // 期待している場合（委任 DID）で、`expectedDid` の DID Document の `authentication` が `kid` を列挙しているときだけ受理する。
  const did = expectedDid ?? kidDid;
  // 解決の失敗（`2001` / `2002` / `2003` / `2010`）は `expectedDid` が `kid` の DID と違っても握り潰さずそのまま伝播する
  // （`3010` は「期待する DID の文書が `kid` を列挙していない」ときだけ。取得できなかった理由を署名不正に取り違えさせない）。
  const document = await opts.resolver.resolve(did);
  if (ownProperty<unknown>(document, 'deactivated') === true) {
    throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
      context: { reason: 'deactivated', relationship: 'authentication' },
    });
  }
  // `authentication` が他 DID の検証メソッド（`kid`）を DID URL 参照で載せているときは、その文書から実体を引く（DID Core §5.3）。
  const inlined = await inlineExternalMethods(opts.resolver, document, 'authentication', { kid });
  const entry = methodsInRelationship(inlined, 'authentication').find(({ id }) => id === kid);
  if (entry === undefined) {
    if (did !== kidDid) {
      throw invalid('did_mismatch');
    }
    throw new VericertsError(ErrorCodes.DID_KEY_MISMATCH, {
      context: { reason: 'relationship_not_granted', relationship: 'authentication' },
    });
  }
  const signingInput = signingInputOf(headerSegment, message);
  if (!verifyWithMethod(alg, { signingInput, signature }, entry.method)) {
    throw invalid('signature');
  }
  return { did, kid, alg };
}
