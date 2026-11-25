/**
 * DIF Credential Manifest の取得・パース（Holder 側）。
 *
 * `parseCredentialManifest` は生 JSON を構造検証して `CredentialManifest` にする（3031 / 3032）。
 * `fetchCredentialManifest` は HTTPS で取得しパースする（3034）。共有の構造判定ヘルパも提供し、
 * `application.ts` から再利用する。
 *
 * セキュリティ: 例外 message / context に応答本文・VC 本文を含めない。
 * 取得は HTTPS のみ許可する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveInjectedFetch } from '../../fetch-di.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from '../../http/body-limit.js';
import { isPublicHttpsUrl } from '../../http/public-https-url.js';
import {
  bindForPublicRedirects,
  fetchFollowingPublicRedirects,
} from '../../http/public-redirect-fetch.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { isLoA } from '../evidence-tou/evidence.js';
import { isPlainObject } from '../object-guards.js';
import {
  type CredentialManifest,
  MANIFEST_REQUEST_TIMEOUT_MS,
  type ManifestDependencies,
  type ManifestIssuer,
  type OutputDescriptor,
  type PresentationDefinition,
  SUPPORTED_SPEC_VERSION_PREFIXES,
} from './types.js';

/**
 * 横断ヘルパーの再エクスポート。判定ロジックはそちらに集約し、既存の import パス
 * （`./parse.js` 経由）は後方互換のため維持する。
 *
 * - `isHttpsUrl`: URL として解釈でき、かつスキームが `https:` かを検証する
 *   （`internal/https-url.ts` へ集約）。
 * - `isPlainObject`: 配列を除く非 null オブジェクトかを判定する
 *   （`internal/credential/object-guards.ts` へ集約）。
 */
export { isHttpsUrl } from '../../https-url.js';
export { isPlainObject };

/** `spec_version` が本 SDK の対応範囲かを判定する。 */
function isSupportedSpecVersion(specVersion: string): boolean {
  return SUPPORTED_SPEC_VERSION_PREFIXES.some((prefix) => specVersion.startsWith(prefix));
}

/**
 * ManifestIssuer を構造検証して読み取り専用に固める。
 *
 * `raw` は公開 API `parseCredentialManifest(raw)` から**呼び出し側が組み立てたオブジェクト**が
 * 渡り得る。`fetchCredentialManifest`
 * 経由の場合は `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**である。
 * いずれの経路でもメンバは**自身のプロパティに限って**読む。鎖読みだと `issuer.id` を持たない Manifest でも
 * `Object.prototype.id` の汚染値が採用され、その値が `submitCredentialApplication` の
 * POST 先（`submitEndpoint` 未指定時の既定）になるため申請が攻撃者のエンドポイントへ飛ぶ
 * （`application.ts` 側も同じ own 限定で読む）。各メンバは検査と採用を**同じ 1 回の読み取り結果**で行う
 * （アクセサでは 2 度読みするとガードを通した値と採用値が食い違う）。
 */
function parseIssuer(raw: unknown): ManifestIssuer {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const id = ownProperty<unknown>(raw, 'id');
  if (!isNonBlankString(id)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const name = ownProperty<unknown>(raw, 'name');
  const styles = ownProperty<unknown>(raw, 'styles');
  return {
    id,
    ...(isNonBlankString(name) ? { name } : {}),
    ...(isPlainObject(styles) ? { styles } : {}),
  };
}

/**
 * OutputDescriptor を構造検証する。`id` と `schema` は DIF 必須。
 *
 * `parseIssuer` と同じ理由でメンバは own 限定・1 回読みにする。
 */
function parseOutputDescriptor(raw: unknown): OutputDescriptor {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const id = ownProperty<unknown>(raw, 'id');
  const schema = ownProperty<unknown>(raw, 'schema');
  if (!isNonBlankString(id) || !isNonBlankString(schema)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const name = ownProperty<unknown>(raw, 'name');
  const description = ownProperty<unknown>(raw, 'description');
  const styles = ownProperty<unknown>(raw, 'styles');
  const display = ownProperty<unknown>(raw, 'display');
  return {
    id,
    schema,
    ...(isNonBlankString(name) ? { name } : {}),
    ...(isNonBlankString(description) ? { description } : {}),
    ...(isPlainObject(styles) ? { styles } : {}),
    ...(isPlainObject(display) ? { display } : {}),
  };
}

/**
 * presentation_definition を最小構造検証する（`id` 必須、残りは不透明）。
 *
 * `id` は own 限定・1 回読みで検証する。それ以外のメンバは本 SDK が解釈しない不透明な PEx v2
 * 構造として `raw` をそのまま返す（呼び出し側は `id` 以外を own 限定で読む必要はない）。
 */
function parsePresentationDefinition(raw: unknown): PresentationDefinition {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const id = ownProperty<unknown>(raw, 'id');
  if (!isNonBlankString(id)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  return raw as PresentationDefinition;
}

/**
 * 生 JSON（object）を DIF Credential Manifest として構造検証しパースする。
 *
 * 検証: `id` / `spec_version` / `issuer.id` / `output_descriptors`（1 件以上、各 id・schema 必須）が
 * 揃っていること。欠落・型不正は `MANIFEST_SCHEMA_INVALID`（3031）。`spec_version` が未対応なら
 * `MANIFEST_SPEC_VERSION_UNSUPPORTED`（3032）。
 *
 * `raw` は公開 API `parseCredentialManifest(raw)` から**呼び出し側が組み立てたオブジェクト**が
 * 渡り得る。`fetchCredentialManifest`
 * 経由の場合は `parseJsonWithoutPrototype` を通るため **`null` プロトタイプ**である。
 * いずれの経路でもメンバは**自身のプロパティに限って**（own 限定・1 回読みで）読む。鎖読みだと、例えば `output_descriptors`
 * を持たない Manifest でも `Object.prototype.output_descriptors` の汚染値が「1 件以上の配列」と
 * 見なされて素通りするなど、必須フィールド欠落チェックそのものが無効化される。
 *
 * @param raw JSON パース済みの未知の入力。
 * @throws スキーマ不正（3031）/ 未対応バージョン（3032）。
 */
export function parseCredentialManifest(raw: unknown): CredentialManifest {
  if (!isPlainObject(raw)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const id = ownProperty<unknown>(raw, 'id');
  const specVersion = ownProperty<unknown>(raw, 'spec_version');
  if (!isNonBlankString(id) || !isNonBlankString(specVersion)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  // spec_version の対応判定はスキーマ検証（3031）と分離し、対応外は 3032 を返す。
  if (!isSupportedSpecVersion(specVersion)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SPEC_VERSION_UNSUPPORTED);
  }
  const outputDescriptors = ownProperty<unknown>(raw, 'output_descriptors');
  if (!Array.isArray(outputDescriptors) || outputDescriptors.length === 0) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const issuer = ownProperty<unknown>(raw, 'issuer');
  const format = ownProperty<unknown>(raw, 'format');
  const presentationDefinition = ownProperty<unknown>(raw, 'presentation_definition');
  // `required_loa`も他メンバと同じく own 限定・1 回読みで検証する。未指定は
  // 許容するが、告知された値が `isLoA` を満たさない場合はスキーマ不正（3031）として拒否する
  // （`auth/request.ts` の `requiredLoA` と同様、不正値を「未指定」へ丸めない）。
  const requiredLoA = ownProperty<unknown>(raw, 'required_loa');
  if (requiredLoA !== undefined && !isLoA(requiredLoA)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }

  return {
    id,
    spec_version: specVersion,
    issuer: parseIssuer(issuer),
    output_descriptors: outputDescriptors.map(parseOutputDescriptor),
    ...(isPlainObject(format) ? { format } : {}),
    ...(presentationDefinition !== undefined
      ? { presentation_definition: parsePresentationDefinition(presentationDefinition) }
      : {}),
    ...(requiredLoA !== undefined ? { required_loa: requiredLoA } : {}),
  };
}

/**
 * DIF Credential Manifest を HTTPS で取得しパースする。
 *
 * HTTPS 以外・HTTP エラー・ネットワーク失敗・JSON パース失敗は `MANIFEST_FETCH_FAILED`（3034）。
 * 取得後の構造検証は `parseCredentialManifest` に委譲する（3031 / 3032）。
 *
 * `deps.fetchImpl` は関数値 DI なので `resolveInjectedFetch`（`internal/fetch-di.ts` の
 * 共有ヘルパー）で解決する。own 限定で読むと prototype メソッドで注入した正当な DI が無言で
 * グローバル `fetch` に差し替わり（fail-open）、逆に鎖読みだと `Object.prototype` 汚染下で
 * `fetchImpl` を指定していない正当な呼び出しが攻撃者の fetch に委譲される。取り出した関数は
 * 取り出し元（`deps`）をレシーバに束ねて呼ぶ。
 *
 * @param manifestURL Manifest の HTTPS URL。
 * @throws 取得失敗（3034）/ スキーマ不正（3031）/ 未対応バージョン（3032）。
 */
export async function fetchCredentialManifest(
  manifestURL: string,
  deps: ManifestDependencies = {},
): Promise<CredentialManifest> {
  if (!isPublicHttpsUrl(manifestURL)) {
    throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
  }

  const { doFetch, receiver } = resolveInjectedFetch(deps);
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。ヘッダだけ先に
  // 返して本文を引き延ばす取得先に無限に待たないため（`internal/http/fetch-json.ts` の不変条件）。
  const timer = setTimeout(() => controller.abort(), MANIFEST_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // init に `body` を載せない。GET + body は Node/undici とブラウザで `Request` 構築の時点で
      // `TypeError: Request with GET/HEAD method cannot have body.` になり（空文字でも例外）、
      // 実 fetch を使う本番経路が 1 度もネットワークへ到達しない。Bun だけが許容するため、
      // スタブを注入するテストでは表面化しない。リダイレクトは**ホップごとに**公開 HTTPS へ縛って
      // 追従する（`http/public-redirect-fetch.ts`）。`follow` のままだと「公開ホスト → 302 → 内部
      // ホスト」の GET が送出される。
      response = await fetchFollowingPublicRedirects(
        bindForPublicRedirects(doFetch, receiver),
        manifestURL,
        { method: 'GET', headers: { Accept: 'application/json' }, signal: controller.signal },
      );
    } catch {
      // ネットワークエラー / タイムアウト（abort）。詳細は載せない。
      throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
    }

    // 最終 URL の再検査（多層防御）。ブラウザの `opaqueredirect` は上の取得で失敗に倒れる。
    if (response.url.length > 0 && !isPublicHttpsUrl(response.url)) {
      throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
    }
    if (!response.ok) {
      throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
    }
    // 自己申告の `content-length` で早期に落とし、実バイト数でも上限（1 MiB）で打ち切る。
    if (declaresOversizedBody(response)) {
      throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
    }

    let parsed: unknown;
    try {
      const text = await readBodyWithinLimit(response);
      if (text === undefined) {
        // 上限超過。
        throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
      }
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      // 本文読み出し中のネットワークエラー / abort / 上限超過 / パース失敗。本文は message に載せない。
      throw new VericertsError(ErrorCodes.MANIFEST_FETCH_FAILED);
    }

    return parseCredentialManifest(parsed);
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
