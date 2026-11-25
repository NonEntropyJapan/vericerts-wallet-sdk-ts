/**
 * PEx v2 `presentation_submission` の既定構築（`direct_post` / `direct_post.jwt` の送信用）。
 *
 * Verifier が `presentation_definition`
 * で要求した提示には `presentation_submission` を添える（OID4VP §6.1 / PEx v2）。walt.id verifier は
 * `presentation_submission` の `descriptor_map[0].format` で VP の検証方式を選ぶため、欠落すると
 * HTTP 400（`No presentation submission or presentation format found.`）で拒否する。
 *
 * 対象は「1 本の JWT-VP（`jwt_vp_json`）に VC-JWT（`jwt_vc_json`）を束ねた」提示だけである。
 * `buildVPToken` が構成する `jwt_vc_json` 提示がこれに当たる。SD-JWT VC・mdoc・複数 VP は
 * descriptor の対応付けを呼び出し側が決めるしかないため、既定では構築せず
 * `SubmitPresentationOptions.presentationSubmission` の明示指定に委ねる。
 */

import { base64urlnopad } from '@scure/base';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { FORMAT_JWT_VC } from '../matcher.js';
import type { PresentationRequest } from '../request.js';

/** 外側 VP の format 識別子（OID4VP の format レジストリ）。VC 側は `FORMAT_JWT_VC`。 */
const FORMAT_JWT_VP = 'jwt_vp_json';

/** JWT（`header.payload.signature`。`~` を含む SD-JWT は対象外）かを判定する。 */
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

/**
 * VP-JWT の `vp.verifiableCredential` の件数を返す。読めない・配列でない場合は 0。
 * 不正な形（payload が JSON でない・`vp` が無い等）は `ownProperty` / `JSON.parse` の例外で 0 に倒す。
 */
function countEmbeddedCredentials(vpJwt: string): number {
  try {
    const payload: object = JSON.parse(
      new TextDecoder().decode(base64urlnopad.decode(vpJwt.split('.')[1] ?? '')),
    );
    const vp = ownProperty<object>(payload, 'vp') as object;
    const credentials = ownProperty<unknown>(vp, 'verifiableCredential');
    return Array.isArray(credentials) ? credentials.length : 0;
  } catch {
    return 0;
  }
}

/** `presentation_definition` の `input_descriptors[].id` を順に返す。1 つでも文字列 id が無ければ空。 */
function inputDescriptorIds(presentationDefinition: Readonly<Record<string, unknown>>): string[] {
  const descriptors = ownProperty<unknown[]>(presentationDefinition, 'input_descriptors');
  const ids = Array.isArray(descriptors)
    ? descriptors.map((d) =>
        typeof d === 'object' && d !== null ? ownProperty(d, 'id') : undefined,
      )
    : [];
  return ids.every((id) => typeof id === 'string') ? (ids as string[]) : [];
}

/**
 * `presentation_definition` 経路の要求に対する既定の `presentation_submission` を構築する。
 *
 * `input_descriptors[i]` を VP 内の `i` 番目の VC（`$.vp.verifiableCredential[i]`）へ対応付ける。
 * VP が持つ VC 数が descriptor 数より少ない場合は、持つ分だけを対応付ける。
 *
 * @returns 構築した submission。DCQL 要求・対象外の `vpToken`・descriptor / VC が無い場合は `undefined`。
 */
function buildDefaultPresentationSubmission(
  request: PresentationRequest,
  vpToken: string | string[],
): Record<string, unknown> | undefined {
  const presentationDefinition = ownProperty<Readonly<Record<string, unknown>>>(
    request,
    'presentationDefinition',
  );
  if (presentationDefinition === undefined || typeof vpToken !== 'string') {
    return undefined;
  }
  const definitionId = ownProperty<unknown>(presentationDefinition, 'id');
  if (typeof definitionId !== 'string' || !JWT_PATTERN.test(vpToken)) {
    return undefined;
  }
  const descriptorIds = inputDescriptorIds(presentationDefinition);
  const mapped = Math.min(descriptorIds.length, countEmbeddedCredentials(vpToken));
  if (mapped === 0) {
    return undefined;
  }
  return {
    id: crypto.randomUUID(),
    definition_id: definitionId,
    descriptor_map: descriptorIds.slice(0, mapped).map((id, index) => ({
      id,
      format: FORMAT_JWT_VP,
      path: '$',
      path_nested: { id, format: FORMAT_JWT_VC, path: `$.vp.verifiableCredential[${index}]` },
    })),
  };
}

/**
 * 送信に載せる `presentation_submission` を決める。呼び出し側の明示指定を優先し、無ければ
 * `presentation_definition` 経路の要求に限り既定の submission を構築する（DCQL では `undefined`）。
 *
 * `options.presentationSubmission` は自身のプロパティに限って読む。`options.x !== undefined` は
 * プロトタイプ鎖を辿るため、渡していない正当な呼び出しでも汚染値を Verifier へ送ってしまう。
 */
export function resolvePresentationSubmission(
  request: PresentationRequest,
  vpToken: string | string[],
  options: { readonly presentationSubmission?: Readonly<Record<string, unknown>> },
): Readonly<Record<string, unknown>> | undefined {
  return (
    ownProperty<Readonly<Record<string, unknown>>>(options, 'presentationSubmission') ??
    buildDefaultPresentationSubmission(request, vpToken)
  );
}
