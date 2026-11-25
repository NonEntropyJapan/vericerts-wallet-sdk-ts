/**
 * DIF Credential Application の提出と Credential Response 処理（Holder 側）。
 *
 * - `processCredentialResponse`: Issuer の Credential Response（fulfillment / denial / 遅延発行）を
 *   解釈し、fulfillment 時は DI で受領 VC を検証して `ApplicationResult` にする。
 * - `submitCredentialApplication`: Application 構築 → Issuer へ POST → Response 処理のエンドツーエンド。
 *
 * HTTP・VC 検証は DI（`fetchImpl` / `verifyReceived`）で外出しし、純粋なプロトコルロジックとして
 * 単体テスト可能にする。例外 message / context に VC 本文・応答本文を含めない。
 *
 * Application 構築（`buildCredentialApplication`）は `application-build.ts` を参照
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../http/public-https-url.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { VerifiableCredential } from '../vc/vc.js';
import { buildCredentialApplication } from './application-build.js';
import { isPlainObject } from './parse.js';
import {
  type ApplicationResult,
  type BuildApplicationOptions,
  type CredentialManifest,
  MANIFEST_REQUEST_TIMEOUT_MS,
  type ManifestAnswers,
  type SubmitApplicationDependencies,
} from './types.js';

/**
 * 非空文字列のみを返す。それ以外（欠落・非文字列・空白のみ）は `undefined`。
 *
 * own 限定で読んでも型は保証されないため、判定は共有ヘルパ `isNonBlankString`
 * （`internal/prototype-safety/non-empty-string.ts`）に委ねる。値は呼び出し側で**1 回だけ読んだもの**
 * を受け取る。同じキーを検査用と採用用に 2 度読むと、アクセサでは呼ばれるたびに別の値を返せる
 * ため、ガードを通した値と実際に採用される値が食い違う（TOCTOU）。
 */
function toNonEmptyStringOrUndefined(value: unknown): string | undefined {
  return isNonBlankString(value) ? value : undefined;
}

/**
 * Issuer の Credential Response を解釈して `ApplicationResult` にする。
 *
 * DIF Credential Response は fulfillment（発行成功）または denial（却下）のいずれか。
 * - `verifiableCredential` / `credential` に生 VC があれば `verify` で検証し、成功で
 *   `{ accepted: true, credential }`。検証失敗は Issuer 起因の受領 VC 検証失敗として
 *   `REFRESHED_VC_VERIFICATION_FAILED`（3022）で扱う。
 * - `transaction_id` があれば遅延発行として `{ accepted: true, transactionId }`。
 * - `denial` / `rejectionReason` があれば `{ accepted: false, rejectionReason }`。
 * - いずれも判別できない構造は `MANIFEST_SCHEMA_INVALID`（3031）。
 *
 * `raw` は `unknown` 受けで、`fetch` 応答（`parseJsonWithoutPrototype` 由来＝プロトタイプなし）だけで
 * なく**呼び出し側が組み立てたオブジェクト**も渡りうる。後者は `Object.prototype` を継承するため、
 * 応答メンバはオブジェクト自身のプロパティに限って読む。継承値を許すと Issuer が `{}` を返しただけで
 * `Object.prototype.transaction_id` の汚染値が遅延発行の取引 ID として、
 * `Object.prototype.rejectionReason` の汚染値が却下理由として（denial は fulfillment より先に
 * 判定されるため正当な応答すら却下に化ける）、`Object.prototype.credential` の汚染値が受領 VC として
 * 採用される。`isNonBlankString` / `isPlainObject` のガードは汚染値が非空文字列 / オブジェクトなら
 * 素通りするため防げない。いずれも純データなので own 限定（`ownProperty`）でよい。
 *
 * 戻り値のオブジェクトリテラルは `ApplicationResult` の 4 キーすべてを（値が `undefined` でも）
 * **自身のプロパティとして**定義する。条件付きスプレッドでキーを落とすと、呼び出し側の
 * `result.credential` 等が汚染された `Object.prototype` へ到達し、ここでの own 化が無効化される。
 *
 * @param raw JSON パース済みの Credential Response（未知の入力でもよい）。
 * @param verify 受領 VC を検証する DI 関数。
 * @throws 受領 VC 検証失敗（3022）/ 判別不能な構造（3031）。
 */
export async function processCredentialResponse(
  raw: unknown,
  verify: (rawCredential: string) => Promise<VerifiableCredential>,
): Promise<ApplicationResult> {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }

  // 却下（denial）。理由は表示用の非機密文字列のみ拾う。外側 `denial` / フラットな
  // `rejectionReason` に加え、`denial` の内側 `reason` も own 限定で読む（外側だけ own 化すると
  // 内側に穴が残る）。
  const denial = ownProperty<unknown>(raw, 'denial');
  const nestedReason = isPlainObject(denial) ? ownProperty<unknown>(denial, 'reason') : undefined;
  const denialReason =
    toNonEmptyStringOrUndefined(nestedReason) ??
    toNonEmptyStringOrUndefined(ownProperty<unknown>(raw, 'rejectionReason'));
  if (denialReason !== undefined) {
    return {
      accepted: false,
      transactionId: undefined,
      credential: undefined,
      rejectionReason: denialReason,
    };
  }

  // 即時発行（fulfillment）。生 VC 文字列を検証する。
  const rawVc =
    toNonEmptyStringOrUndefined(ownProperty<unknown>(raw, 'verifiableCredential')) ??
    toNonEmptyStringOrUndefined(ownProperty<unknown>(raw, 'credential'));
  if (rawVc !== undefined) {
    let credential: VerifiableCredential;
    try {
      credential = await verify(rawVc);
    } catch {
      // 受領 VC の署名 / スキーマ / 失効検証失敗。原因（VC 本文）は message に載せない。
      throw new VericertsError(ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED);
    }
    return {
      accepted: true,
      transactionId: undefined,
      credential,
      rejectionReason: undefined,
    };
  }

  // 遅延発行（transaction_id）。
  const transactionId =
    toNonEmptyStringOrUndefined(ownProperty<unknown>(raw, 'transaction_id')) ??
    toNonEmptyStringOrUndefined(ownProperty<unknown>(raw, 'transactionId'));
  if (transactionId !== undefined) {
    return {
      accepted: true,
      transactionId,
      credential: undefined,
      rejectionReason: undefined,
    };
  }

  // fulfillment でも denial でもない判別不能な応答。
  throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
}

/**
 * Manifest への申請を Issuer に提出し結果を返す。
 *
 * 手順: (1) `buildCredentialApplication` で Application を構築（要件未充足で 3080）。
 * (2) Manifest の issuer.id が HTTPS の申請エンドポイントであることを要求し、`POST` で Application を
 * 送信する（HTTPS 以外 / HTTP エラー / ネットワーク失敗で `ISSUER_COMMUNICATION_FAILED` 3004）。
 * (3) 応答 JSON を `processCredentialResponse` で解釈する（受領 VC 検証は `verifyReceived` に委譲）。
 *
 * DIF は申請の送信先を Manifest 外の Issuer Metadata で規定するが、本 SDK は最小構成として
 * `manifest.issuer.id` が HTTPS URL の場合にそこへ POST する。DID 等 URL でない場合は
 * `submitEndpoint` の明示指定を必須とする。
 *
 * `opts.submitEndpoint` と `manifest.issuer` / `manifest.issuer.id` はいずれも純データ（送信先 URL）
 * なので own 限定（`ownProperty`）で読む。`Object.prototype` のこれらのキーが汚染されると、
 * `submitEndpoint` を渡さない正当な呼び出しが攻撃者の HTTPS エンドポイントへ Application を
 * POST してしまう。`deps.fetchImpl` は関数値 DI なので `resolveInjectedFetch`
 * （`internal/fetch-di.ts` の共有ヘルパー）で解決し、
 * 取り出した関数は `deps` をレシーバにして呼ぶ。
 *
 * @param manifest 対象 Manifest。
 * @param answers 申請回答。
 * @param deps 検証・HTTP の DI。
 * @param opts フォーマット / ID 生成 / 送信先（`submitEndpoint`）の注入。
 * @throws 要件未充足（3080）/ 送信先不正・通信失敗（3004）/ 受領 VC 検証失敗（3022）/ 構造不正（3031）。
 */
export async function submitCredentialApplication(
  manifest: CredentialManifest,
  answers: ManifestAnswers,
  deps: SubmitApplicationDependencies,
  opts: BuildApplicationOptions & { readonly submitEndpoint?: string } = {},
): Promise<ApplicationResult> {
  const application = buildCredentialApplication(manifest, answers, opts);

  // `manifest.issuer` とその `id` も純データなので own 限定で読む（`parse.ts` の `parseIssuer` と
  // 同型の `isPlainObject` → `ownProperty` → 非空文字列検査）。鎖読みだと own の `issuer` を
  // 持たない Manifest で `Object.prototype.issuer`（あるいは `issuer` は own でも
  // `Object.prototype.id`）の汚染値が送信先になり、`submitEndpoint` を明示しない正当な呼び出しが
  // 攻撃者のエンドポイントへ Application を POST してしまう。
  const issuer = ownProperty<unknown>(manifest, 'issuer');
  const issuerId = isPlainObject(issuer) ? ownProperty<unknown>(issuer, 'id') : undefined;
  const endpoint = ownProperty<string>(opts, 'submitEndpoint') ?? issuerId;
  if (!isNonBlankString(endpoint) || !isPublicHttpsUrl(endpoint)) {
    // DID 等で送信先が定まらない / 非 HTTPS。呼び出し側が submitEndpoint を明示する必要がある。
    throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
  }

  const { doFetch, receiver } = resolveInjectedFetch(deps);
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), MANIFEST_REQUEST_TIMEOUT_MS);
  let parsed: unknown;
  let response: Response | undefined; // 読まずに throw する経路でも finally で解放する。
  try {
    try {
      response = await doFetch.call(receiver, endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ credential_application: application }),
        // 3xx に追従して Credential Application を別ホストへ再送しない。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    if (isRedirectedResponse(response)) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
    try {
      // 自己申告の `content-length` と実バイト数の双方に 1 MiB 上限を課す。本文は message に載せない。
      const declaredTooLarge = declaresOversizedBody(response);
      const text = declaredTooLarge ? undefined : await readBodyWithinLimit(response);
      if (text === undefined) {
        throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
      }
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
    }
  } finally {
    clearTimeout(timer);
    discardBody(response); // 読まない本文を解放する（読了後は no-op）。
  }

  // `verifyReceived` は関数値 DI であり、`class Deps { async verifyReceived(raw) {…} }` の
  // ようにプロトタイプメソッドとして実装するのが正当なため own 限定では読めない（own 限定にすると
  // 「未指定」と判定され fail-closed に倒れず沈黙してしまう）。一方で `Object.prototype` を
  // そのまま辿ると、汚染された `Object.prototype.verifyReceived` が受領 VC 検証器として採用され
  // うる。`nonObjectPrototypeProperty` で `Object.prototype` 由来だけを弾く
  // （`credential/refresh/refresh.ts` の `verifyRefreshed` と同じ規律）。
  const verifyReceived = nonObjectPrototypeProperty<
    SubmitApplicationDependencies['verifyReceived']
  >(deps, 'verifyReceived');
  if (typeof verifyReceived !== 'function') {
    // 検証器が無ければ受領 VC を受理できない（fail-closed）。
    throw new VericertsError(ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED);
  }
  // 取り出した関数は取り出し元（`deps`）をレシーバに束ね直して呼ぶ。裸で
  // 呼ぶと、従来 `deps.verifyReceived(raw)` で成立していた `this` 参照つき実装が壊れる。
  return processCredentialResponse(parsed, verifyReceived.bind(deps));
}
