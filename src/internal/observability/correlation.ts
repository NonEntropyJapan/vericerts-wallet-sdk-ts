/**
 * 相関 ID の生成と伝播。
 *
 * アプリケーションから SDK を経由して Issuer / Verifier へ伝播させる
 * 識別子——W3C Trace Context の `traceparent` / `tracestate` と、ユーザー操作単位で発行する
 * `X-Request-Id`——を 1 つの値にまとめ、HTTP ヘッダ形へ落とす。
 *
 * 本モジュールは自己完結の純関数のみで構成する（HTTP 呼び出し側への結線は別レイヤの責務）。
 * 上流から渡された `traceparent` が壊れていても例外は投げず、新しいトレースを起こして続行する。
 * 相関 ID は観測のための補助情報であり、その不備でウォレットの処理を止める理由がないため。
 *
 * `traceparent` は hex のトレース情報で、
 * `tracestate` は任意の key=value を載せられるため、`user.*` / `did:*` を含むエントリは
 * SDK 側で strip する（呼び出し側の実装ミスで識別子が外部へ出ることを防ぐ）。
 *
 * 型は本モジュール（横断）に置き、`wallet/options.ts` が公開 API として再エクスポートする
 * （内部モジュールから公開 API 層への依存を避けるため）。
 */

import { bytesToHex } from '@noble/hashes/utils.js';
import { ownProperty } from '../prototype-safety/own-property.js';

/**
 * 1 回のユーザー操作に紐づく相関 ID の組。
 *
 * この値を SDK 内部で持ち回り、外向きリクエストのヘッダ（{@link correlationHeaders}）と
 * 構造化ログ / メトリクスの双方へ同じ ID を載せることで、UI 操作から Issuer / Verifier の
 * 応答までを 1 本に繋ぐ。
 */
export interface CorrelationContext {
  /** ユーザー操作単位の識別子（`X-Request-Id`）。 */
  readonly requestId: string;
  /** W3C Trace Context の `traceparent`（`00-<trace-id>-<parent-id>-<flags>`）。 */
  readonly traceparent: string;
  /** W3C Trace Context の `tracestate`。ユーザー識別子を含むエントリを取り除いた後、残りがなければ省略される。 */
  readonly tracestate?: string;
}

/**
 * {@link createCorrelationContext} の入力（すべて任意）。
 *
 * 上流（Popup / Background SW）が既に発行した ID を引き継ぐための口。省略・不正値のときは
 * その項目だけ新規生成する。
 */
export interface CreateCorrelationContextInput {
  /** 引き継ぐ `X-Request-Id`。空白のみ・非文字列なら新規生成する。 */
  readonly requestId?: string;
  /** 引き継ぐ `traceparent`。W3C 形式として不正なら新しいトレースを起こす。 */
  readonly traceparent?: string;
  /** 引き継ぐ `tracestate`。ユーザー識別子を含むエントリを取り除いてから格納する。 */
  readonly tracestate?: string;
}

/** `traceparent` の version（W3C Trace Context Level 1 は `00` のみ）。 */
const TRACEPARENT_VERSION = '00';

/** `traceparent` の trace-flags。`01` は sampled を表す。実際のサンプリングはサンプラが決める。 */
const TRACEPARENT_SAMPLED_FLAGS = '01';

/** trace-id のバイト数（hex 32 桁）。 */
const TRACE_ID_BYTES = 16;

/** parent-id（span-id）のバイト数（hex 16 桁）。 */
const PARENT_ID_BYTES = 8;

/** `X-Request-Id` のバイト数（hex 32 桁 = 128 bit）。 */
const REQUEST_ID_BYTES = 16;

/** `traceparent` の形（version-trace_id-parent_id-flags）。hex は小文字のみ許す（W3C 準拠）。 */
const TRACEPARENT_PATTERN = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

/** W3C Trace Context が禁じる `traceparent` の version。 */
const FORBIDDEN_TRACEPARENT_VERSION = 'ff';

/** 全ゼロの hex。W3C Trace Context は trace-id / parent-id の全ゼロを無効値と定める。 */
const ALL_ZERO_HEX_PATTERN = /^0+$/;

/** ユーザー識別子とみなすキー / 値（`user.*`）。 */
const USER_IDENTIFIER_PATTERN = /^user\./;

/**
 * ヘッダから除外する DID（`did:<method>:<id>`）。前方一致ではなく部分一致で見る。
 *
 * `vendor=trace-did:key:z6Mk…` のように値の途中へ埋め込まれた DID も落とすため。相関 ID の
 * 欠落より識別子の漏洩の方が実害が大きく、過剰に strip する側へ倒す。
 */
const DID_PATTERN = /did:[a-z0-9]+:/i;

/**
 * `X-Request-Id` として送ってよい値の形。可視 ASCII（`\x21-\x7e`、空白・CR/LF・非 Latin-1 を含まない）の
 * 1〜128 文字。ヘッダ値に載せられない値は `Headers` が TypeError を投げ、OID4VP 提示送信ごと失敗する
 * 観測用の補助情報の不備で処理を止めないため、入口でこの形に限る。
 */
const REQUEST_ID_PATTERN = /^[\x21-\x7e]{1,128}$/;

/**
 * CSPRNG で全ゼロでない hex を生成する。
 *
 * `crypto.getRandomValues` は browser / Node.js / Bun のいずれでも利用できる（`nonce/generate.ts`
 * と同じ乱数源）。全ゼロは W3C が禁じる値のため、引いてしまった場合は 1 bit だけ立てる。
 * 値を捨てて引き直すより分岐が単純で必ず終わり、偏りは 2^-128 相当で無視できる。
 *
 * @param byteLength 生成するバイト数。
 * @returns 小文字 hex 文字列（長さは `byteLength * 2`）。
 */
function randomNonZeroHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  if (bytes.every((byte) => byte === 0)) {
    bytes[byteLength - 1] = 1;
  }
  return bytesToHex(bytes);
}

/** 新しいトレースを起こす（sampled 固定）。 */
function generateTraceparent(): string {
  const traceId = randomNonZeroHex(TRACE_ID_BYTES);
  const parentId = randomNonZeroHex(PARENT_ID_BYTES);
  return `${TRACEPARENT_VERSION}-${traceId}-${parentId}-${TRACEPARENT_SAMPLED_FLAGS}`;
}

/**
 * 上流から渡された `traceparent` をそのまま引き継いでよいか判定する。
 *
 * 形式に加えて trace-id / parent-id の全ゼロを弾く。全ゼロを通すと W3C 上無効なトレースを
 * 下流へ伝播させ、受け側の Collector に捨てられて相関が途切れる。
 */
function isValidTraceparent(value: string): boolean {
  if (!TRACEPARENT_PATTERN.test(value)) {
    return false;
  }
  const fields = value.split('-');
  const traceId = fields[1] ?? '';
  const parentId = fields[2] ?? '';
  // W3C Trace Context §3.2.2.1: version `ff` は禁止値。受理すると無効なトレースを下流へ伝播させる。
  return (
    fields[0] !== FORBIDDEN_TRACEPARENT_VERSION &&
    !ALL_ZERO_HEX_PATTERN.test(traceId) &&
    !ALL_ZERO_HEX_PATTERN.test(parentId)
  );
}

/** `tracestate` の 1 エントリがユーザー識別子を含むか（`user.*` / `did:*`）。 */
function containsUserIdentifier(entry: string): boolean {
  const separatorIndex = entry.indexOf('=');
  // `=` の無い壊れたエントリはキーだけが書かれたものとみなし、同じ基準で検査する。
  const key = separatorIndex === -1 ? entry : entry.slice(0, separatorIndex);
  const value = separatorIndex === -1 ? '' : entry.slice(separatorIndex + 1);
  return [key, value].some(
    (token) => USER_IDENTIFIER_PATTERN.test(token) || DID_PATTERN.test(token),
  );
}

/**
 * `tracestate` からユーザー識別子を載せたエントリを取り除く。
 *
 * @param value カンマ区切りの `key=value` 列。
 * @returns 残ったエントリを連結した文字列。1 つも残らなければ `undefined`（空文字は返さない）。
 */
function sanitizeTracestate(value: string): string | undefined {
  const kept = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0 && !containsUserIdentifier(entry));
  return kept.length > 0 ? kept.join(',') : undefined;
}

/**
 * `requestId` をヘッダへ載せてよいか。形（{@link REQUEST_ID_PATTERN}）に加え、DID を
 * 含む値は外部へ出さない（`tracestate` と同じ基準。`did:ethr:0x…` を `X-Request-Id` に載せない）。
 */
function isSafeRequestId(value: string): boolean {
  return REQUEST_ID_PATTERN.test(value) && !DID_PATTERN.test(value);
}

/**
 * 入力オブジェクトから文字列の任意項目を **own 限定**で読む（`internal/prototype-safety/own-property.ts`）。
 *
 * 純データの任意オプションなので `ownProperty` を使う。プロトタイプ鎖を辿ると、汚染された
 * `Object.prototype` に置かれた `traceparent` を「上流が指定した値」として引き継いでしまい、
 * 攻撃者が選んだトレースへ全リクエストを相関付けられる。
 */
function optionalString(source: object, key: string): string | undefined {
  const value = ownProperty<unknown>(source, key);
  return typeof value === 'string' ? value : undefined;
}

/**
 * 相関 ID の組を組み立てる。
 *
 * 上流から引き継げる項目は引き継ぎ、欠けている・不正な項目だけを新規生成する。どの入力でも
 * 例外は投げない（不正な `traceparent` や、ヘッダに載せられない / DID を含む `requestId` は
 * 黙って新規生成へ倒す）。
 *
 * @param input 上流から引き継ぐ ID。省略時はすべて新規生成する。
 * @returns 常に有効な `requestId` / `traceparent` を持つ相関 ID の組。
 */
export function createCorrelationContext(
  input?: CreateCorrelationContextInput,
): CorrelationContext {
  const requestId = input === undefined ? undefined : optionalString(input, 'requestId');
  const traceparent = input === undefined ? undefined : optionalString(input, 'traceparent');
  const tracestate = input === undefined ? undefined : optionalString(input, 'tracestate');

  const sanitizedTracestate = tracestate === undefined ? undefined : sanitizeTracestate(tracestate);
  return {
    requestId:
      requestId !== undefined && isSafeRequestId(requestId)
        ? requestId
        : randomNonZeroHex(REQUEST_ID_BYTES),
    traceparent:
      traceparent !== undefined && isValidTraceparent(traceparent)
        ? traceparent
        : generateTraceparent(),
    // 空の `tracestate` ヘッダは送らない（フィルタリングで全項目を取り除いた場合も同じ）。
    ...(sanitizedTracestate === undefined ? {} : { tracestate: sanitizedTracestate }),
  };
}

/**
 * 値が {@link CorrelationContext} の形をしているか判定する。
 *
 * 呼び出し側から受け取った相関 ID を SDK 内部で持ち回る前の検査に使う。メンバは純データなので
 * **own 限定**で読む（`ownProperty`）。鎖読みだと、相関 ID を**渡していない**正当な呼び出しでも
 * 汚染された `Object.prototype.traceparent` を「上流が指定した値」として採用し、全リクエストが
 * 攻撃者の選んだトレースへ相関付けられる。
 *
 * `traceparent` は形式（W3C Trace Context Level 1）まで見る。形の壊れた値をヘッダへ載せても
 * 受け側の Collector に捨てられて相関が途切れるだけであり、「持ち回ってよい値」とは言えないため。
 * `requestId` はヘッダ適合（可視 ASCII 1〜128 文字・DID を含まない）まで見る。CRLF や非 Latin-1 は
 * `Headers` の TypeError で提示送信ごと失敗させ、DID は外部へ漏れる。`tracestate` の
 * 識別子を含む `tracestate` エントリの除去は {@link readCorrelationContext} / {@link correlationHeaders} が行う。
 */
export function isCorrelationContext(value: unknown): value is CorrelationContext {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const requestId = ownProperty<unknown>(value, 'requestId');
  const traceparent = ownProperty<unknown>(value, 'traceparent');
  const tracestate = ownProperty<unknown>(value, 'tracestate');
  return (
    typeof requestId === 'string' &&
    isSafeRequestId(requestId) &&
    typeof traceparent === 'string' &&
    isValidTraceparent(traceparent) &&
    (tracestate === undefined || typeof tracestate === 'string')
  );
}

/**
 * オプションオブジェクトの `correlationContext` を **own 限定**で読む。
 *
 * OID4VCI の各プリミティブ（Token / PAR / Credential Request）が、呼び出し側オプションから
 * 相関 ID を取り出すための共通入口。**形が壊れていれば未指定として扱い、例外は投げない**
 * （本モジュール冒頭の方針どおり、観測のための補助情報の不備で受領・提示を止めない）。
 *
 * SDK の入力境界にあたる deps 解決層（`facade` / `authz-flow` の `deps.ts`）は、他の純データ項目と同じく
 * 形の壊れた相関 ID を 8010 で弾く。呼び出し側の実装ミスをそこで気付けるようにしつつ、
 * プリミティブ側は多層防御として黙って落とす、という役割分担である。
 *
 * 手組みの context に対しても `tracestate` からユーザー識別子（`user.*` / `did:*`）を含むエントリを取り除く。
 * 残りがなければ `tracestate` は返さない。
 *
 * @param source 呼び出し側から渡されたオプションオブジェクト。
 * @returns 形の妥当な相関 ID。未指定・不正なら `undefined`。
 */
export function readCorrelationContext(source: object): CorrelationContext | undefined {
  const value = ownProperty<unknown>(source, 'correlationContext');
  if (!isCorrelationContext(value)) {
    return undefined;
  }
  // `value` は呼び出し側が渡した外部入力。省略した `tracestate` で汚染値を拾わないよう、3 キーとも own 限定で読む。
  const requestId = ownProperty<string>(value, 'requestId') as string;
  const traceparent = ownProperty<string>(value, 'traceparent') as string;
  const tracestate = ownProperty<string>(value, 'tracestate');
  const sanitized = tracestate === undefined ? undefined : sanitizeTracestate(tracestate);
  return { requestId, traceparent, ...(sanitized === undefined ? {} : { tracestate: sanitized }) };
}

/**
 * 相関 ID を外向きリクエストのヘッダ形へ落とす。
 *
 * OID4VCI / OID4VP / SIOPv2 のリクエストへそのまま展開して使う。
 *
 * @param context 相関 ID の組。未生成（`undefined`）ならヘッダを足さない。
 * @returns `traceparent` / `X-Request-Id`（と存在すれば `tracestate`）のみを持つヘッダ。
 */
export function correlationHeaders(
  context: CorrelationContext | undefined,
): Record<string, string> {
  if (context === undefined) {
    return {};
  }
  // 型付きの手組み context は `createCorrelationContext` / `readCorrelationContext` を通らないため、
  // 送出口でも `tracestate` を strip し、ヘッダに載せられない / DID を含む `requestId` は
  // 載せない（`Headers` の TypeError で送信ごと失敗させない）。
  const rawTracestate = ownProperty<string>(context, 'tracestate');
  const tracestate = rawTracestate === undefined ? undefined : sanitizeTracestate(rawTracestate);
  // 必須キーも own 限定。省略した手組み context が汚染値を拾って、外向きヘッダに攻撃者の値が載らない。
  const traceparent = ownProperty<unknown>(context, 'traceparent');
  const requestId = ownProperty<unknown>(context, 'requestId');
  return {
    ...(typeof traceparent === 'string' ? { traceparent } : {}),
    ...(typeof requestId === 'string' && isSafeRequestId(requestId)
      ? { 'X-Request-Id': requestId }
      : {}),
    // 空の `tracestate` は送らない（手組みの context が空文字を持っていた場合・strip で全滅した場合）。
    ...(tracestate === undefined ? {} : { tracestate }),
  };
}
