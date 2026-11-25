/**
 * DPoP nonce チャレンジ（RFC 9449 §8 / §9）への 1 回再送。
 *
 * nonce を要求する AS / RS（EUDI / HAIP は nonce の利用が前提）は、nonce を含まない（または失効した）
 * DPoP proof に **`use_dpop_nonce` エラー + `DPoP-Nonce` ヘッダ**で応答する:
 *
 * - AS（Token / PAR）: `400` + 本文 `{"error":"use_dpop_nonce"}`（RFC 9449 §8）。
 * - RS（Credential）: `401` + `WWW-Authenticate: DPoP error="use_dpop_nonce"`（§9）。
 *
 * Wallet はその `DPoP-Nonce` を載せた proof を作り直し、**同じ要求をちょうど 1 回だけ**再送する。
 * 再送後の応答がさらにチャレンジでも再々送はしない（応答の `DPoP-Nonce` を使い回すループは、悪意ある
 * 宛先に proof を何度も署名させる経路になる）。nonce は宛先サーバごとの値（§8 / §9）なので、
 * 別エンドポイントへは持ち越さない。
 *
 * 再送は **proof を持つ要求にだけ**起こる（DPoP を使わない Bearer 経路の挙動は変えない）。proof の
 * 作り直しは呼び出し側が渡す {@link DpopProofRebuilder}（`createDpopProof(htu, { nonce })`）で行う。
 *
 * セキュリティ上の注意: nonce は proof の署名ペイロードに載るだけだが、
 * 宛先が選べる値なので、形（RFC 9449 §8 の `nonce-value` = `1*NQCHAR`）と長さを検査してから使う。
 */

import { discardBody, readBodyWithinLimit } from '../../../http/body-limit.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import type { DpopProof } from '../../dpop/dpop-common.js';
import type { DpopProofContext, DpopProofFactory } from '../oid4vci-credential-dpop.js';

/** サーバが返した `DPoP-Nonce` を載せた proof を作り直す関数。 */
export type DpopProofRebuilder = (nonce: string) => DpopProof;

/** `nonce-value`（RFC 9449 §8）は `1*NQCHAR`（`%x21 / %x23-5B / %x5D-7E`）。上限は過大な値の拒否用。 */
const NONCE_VALUE = /^[\x21\x23-\x5B\x5D-\x7E]{1,512}$/;

/** RS の `WWW-Authenticate: DPoP error="use_dpop_nonce"`（RFC 9449 §9）。 */
const WWW_AUTHENTICATE_USE_DPOP_NONCE = /\berror="use_dpop_nonce"/;

/**
 * AS の本文 `{"error":"use_dpop_nonce"}`（RFC 9449 §8）か。読めない・形が違う本文は `false`。
 * 呼び出し側が通常のエラー処理で本文を読めるよう、複製（`clone()`）を渡すこと。
 */
async function bodyDeclaresUseDpopNonce(response: Response): Promise<boolean> {
  try {
    const text = await readBodyWithinLimit(response);
    const body = text === undefined ? undefined : parseJsonWithoutPrototype(text);
    return (
      typeof body === 'object' && body !== null && ownProperty(body, 'error') === 'use_dpop_nonce'
    );
  } catch {
    return false;
  }
}

/** 応答が nonce チャレンジなら、その `DPoP-Nonce`。そうでなければ `undefined`。 */
async function challengedNonce(response: Response): Promise<string | undefined> {
  if (response.status !== 400 && response.status !== 401) {
    return undefined;
  }
  const nonce = response.headers.get('DPoP-Nonce');
  if (nonce === null || !NONCE_VALUE.test(nonce)) {
    return undefined;
  }
  const authenticate = response.headers.get('WWW-Authenticate');
  const isChallenge =
    (authenticate !== null && WWW_AUTHENTICATE_USE_DPOP_NONCE.test(authenticate)) ||
    (await bodyDeclaresUseDpopNonce(response.clone()));
  return isChallenge ? nonce : undefined;
}

/**
 * `send(dpop)` を実行し、nonce チャレンジを受けたら nonce 付き proof で 1 回だけ再送する。
 *
 * @param send proof（未指定なら `undefined`）を載せて HTTP 要求を 1 回送る関数。
 * @param dpop 初回に載せる proof。`undefined` なら再送せず初回の応答をそのまま返す。
 * @param rebuild nonce 付き proof の生成関数。`undefined` なら再送しない。
 * @returns 最終的な応答（チャレンジを受けていなければ初回のもの）。呼び出し側が通常どおり検査する。
 */
export async function sendWithDpopNonceRetry(
  send: (dpop: DpopProof | undefined) => Promise<Response>,
  dpop: DpopProof | undefined,
  rebuild: DpopProofRebuilder | undefined,
): Promise<Response> {
  const first = await send(dpop);
  if (dpop === undefined || rebuild === undefined) {
    return first;
  }
  const nonce = await challengedNonce(first);
  if (nonce === undefined) {
    return first;
  }
  discardBody(first);
  return send(rebuild(nonce));
}

/**
 * `DpopProofFactory` から、`htu`（と access_token）を固定した {@link DpopProofRebuilder} を作る。
 *
 * @param createDpopProof 呼び出し側の proof 生成関数。未指定なら `undefined`（再送しない）。
 * @param htu 送信先 URL（RFC 9449 §4.3 の HTTP 束縛）。
 * @param context 初回 proof と同じ文脈（Credential Endpoint では access_token）。`nonce` は再送時に加わる。
 */
export function dpopProofRebuilder(
  createDpopProof: DpopProofFactory | undefined,
  htu: string,
  context?: Omit<DpopProofContext, 'nonce'>,
): DpopProofRebuilder | undefined {
  return createDpopProof === undefined
    ? undefined
    : (nonce) => createDpopProof(htu, { ...context, nonce });
}

/**
 * 要求オブジェクトから `rebuildDpop` を own 限定で読む（関数でなければ `undefined` = 再送しない）。
 *
 * 鎖読みだと、指定していない正当な呼び出しが `Object.prototype.rebuildDpop` の汚染関数を再送時に
 * 呼び、攻撃者の proof を `DPoP` ヘッダへ載せうる（`dpop` を own 限定で読むのと同じ理由）。
 */
export function readDpopRebuilder(request: object): DpopProofRebuilder | undefined {
  const rebuild = ownProperty<unknown>(request, 'rebuildDpop');
  return typeof rebuild === 'function' ? (rebuild as DpopProofRebuilder) : undefined;
}
