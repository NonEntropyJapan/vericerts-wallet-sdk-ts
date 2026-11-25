/**
 * DIF Credential Application の構築（Holder 側）。
 *
 * - `buildCredentialApplication`: Manifest に対する Application を構築。presentation_definition が
 *   ある場合は PEx v2 `presentation_submission` を組み立てる。
 *
 * 提出（Issuer への POST）と Credential Response 処理は `application-response.ts` を参照
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import {
  APPLICATION_SPEC_VERSION,
  type BuildApplicationOptions,
  type CredentialApplication,
  type CredentialManifest,
  type ManifestAnswers,
  type PresentationSubmissionDescriptor,
} from './types.js';

/**
 * Application / Submission ID を生成する（DI 優先、既定は crypto.randomUUID）。
 *
 * `opts.generateId` は関数値 DI であり、`class Opts { generateId() {…} }` のようにプロトタイプ
 * メソッドとして実装するのが正当なため own 限定では読めない（own 限定にすると「未指定」と判定され
 * 無言で `crypto.randomUUID()` へフォールバックし、注入した ID 生成器が無視される）。一方で
 * `Object.prototype` 由来の鎖読みだと、`generateId` を指定しない正当な呼び出しが汚染された
 * 生成器へ委譲され、攻撃者が選んだ ID が Application / Submission に載る。`nonObjectPrototypeProperty`
 * で `Object.prototype` 由来だけを弾き、取り出した関数は取り出し元（`opts`）をレシーバに束ねて
 * 呼ぶ（裸で呼ぶと `this` 参照つき実装が壊れる。`internal/fetch-di.ts` と同じ規律）。
 */
export function makeId(opts: BuildApplicationOptions): string {
  const generate = nonObjectPrototypeProperty<() => string>(opts, 'generateId');
  if (typeof generate === 'function') {
    return generate.call(opts);
  }
  return `urn:uuid:${crypto.randomUUID()}`;
}

/**
 * Manifest に対する DIF Credential Application を構築する。
 *
 * Manifest が `presentation_definition` を持つ場合、`answers` の各キー（input_descriptor.id）に対応する
 * PEx v2 `presentation_submission.descriptor_map` を組み立てる。answers が要求 input を満たさない場合は
 * `VC_REQUIREMENT_MISMATCH`（3080）。presentation_definition が無い Manifest では submission を省く。
 *
 * @param manifest 対象 Manifest。
 * @param answers input_descriptor.id をキーとする申請回答。
 * @param opts フォーマット / ID 生成の注入。
 * @throws Manifest が own の `id` を持たない場合（3031）/ 要求 input が answers で満たされない場合（3080）。
 */
export function buildCredentialApplication(
  manifest: CredentialManifest,
  answers: ManifestAnswers,
  opts: BuildApplicationOptions = {},
): CredentialApplication {
  // `manifest` は `parseCredentialManifest` が返すオブジェクトリテラルであり、`format` /
  // `presentation_definition` を持たない正当な Manifest ではこの 2 キーを own プロパティとして
  // 定義しない（条件付きスプレッドで省く）。ただのオブジェクトリテラルなので `Object.prototype` を
  // 継承しており、鎖読み（`manifest.format` / `manifest.presentation_definition`）だと
  // `Object.prototype` が汚染されたときにその値を拾ってしまう。純データ（Manifest の宣言値）
  // なので own 限定（`ownProperty`）で読む。
  const manifestFormat = ownProperty<CredentialManifest['format']>(manifest, 'format');
  // `id` も同じ理由で own 限定にする。`parseCredentialManifest` 経由なら必ず own の非空文字列だが、
  // 公開シグネチャ上は呼び出し側が組み立てた Manifest も渡り得る。鎖読みだと own の `id` を
  // 持たない Manifest で `Object.prototype.id` の汚染値が `manifest_id` として Issuer への
  // POST body に載る。`manifest_id` は必須（`undefined` を許容できない）ため、own の非空文字列が
  // 取れない場合は `parseIssuer` と同じ `MANIFEST_SCHEMA_INVALID`（3031）で fail-closed に倒す。
  const manifestId = ownProperty<unknown>(manifest, 'id');
  if (!isNonBlankString(manifestId)) {
    throw new VericertsError(ErrorCodes.MANIFEST_SCHEMA_INVALID);
  }
  const base: CredentialApplication = {
    id: makeId(opts),
    spec_version: APPLICATION_SPEC_VERSION,
    manifest_id: manifestId,
    ...(manifestFormat !== undefined ? { format: manifestFormat } : {}),
  };

  const definition = ownProperty<CredentialManifest['presentation_definition']>(
    manifest,
    'presentation_definition',
  );
  if (definition === undefined) {
    return base;
  }

  const inputIds = Object.keys(answers);
  if (inputIds.length === 0) {
    // presentation_definition を要求する Manifest なのに回答が無い＝要件未充足。
    throw new VericertsError(ErrorCodes.VC_REQUIREMENT_MISMATCH);
  }

  // `presentationFormat` は純データ（PEx `format` 識別子の文字列）なので own 限定で読む。
  // `Object.prototype` の汚染下で `presentationFormat` を省略した正当な呼び出しでも、鎖読みだと
  // 汚染値が採用され、提示 VC のフォーマット表明が攻撃者の選んだ値へ書き換わる。
  const presentationFormat = ownProperty<string>(opts, 'presentationFormat') ?? 'jwt_vc_json';
  const descriptorMap: PresentationSubmissionDescriptor[] = inputIds.map((inputId, index) => ({
    id: inputId,
    format: presentationFormat,
    path: `$.verifiableCredential[${index}]`,
  }));

  return {
    ...base,
    presentation_submission: {
      id: makeId(opts),
      definition_id: definition.id,
      descriptor_map: descriptorMap,
    },
  };
}
