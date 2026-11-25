/**
 * 外部由来 JSON の応答本文に課す入口検査（Content-Type / サイズ上限）— 横断プリミティブ。
 *
 * 「Issuer / 検証対象ドメインが指す URL から JSON を取る」経路は SDK に複数ある
 * （`credential/json-schema/fetch-document.ts` のスキーマ文書取得、
 * `auth/well-known-json/index.ts` の well-known Metadata 取得）。**取得元 URL が攻撃者の影響下に
 * あるという攻撃面は同一**なので、必要な本文検査も同一である。取得そのもの（タイムアウト・
 * 最終 URL の検査・パース）を共有するのは `internal/http/fetch-json.ts` で、本モジュールは
 * そこから呼ばれる**本文検査だけ**を持つ。
 *
 * 既定の本文上限は 1 MiB。呼び出し側は残りのバイト予算に合わせて上限を絞り、失敗を経路固有のエラーに変換できる。
 *
 * タイムアウト・HTTPS 限定・リダイレクト後の最終 URL 検査は取得経路ごとに文脈（束縛する origin の
 * 有無など）が違うため本モジュールには置かない。ここにあるのは**応答が手元に来たあとの本文検査**
 * だけである。
 */

/**
 * 受理するレスポンス本文の最大バイト数（1 MiB）。
 *
 * 取得元は攻撃者が影響し得る URL であり、巨大な応答をそのままメモリに載せると DoS になる。
 * `content-length` は自己申告のため、宣言値（{@link declaresOversizedBody}）と実バイト数
 * （{@link readBodyWithinLimit}）の両方で上限を課す。
 */
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';

export const MAX_DOCUMENT_BYTES = 1_048_576;

/**
 * 上限超過を表す `VericertsError.context.reason` の正規名。
 *
 * 経路ごとに正規化先のエラーコードは違ってよいが（本モジュール冒頭の注記）、**理由の名前は
 * 1 つに揃える**。取得側が立てた理由を別モジュールが読んで分類する経路（Federation の
 * `fail-open/fetch-failure.ts` は上限超過を fail-open の入力から外す）があり、両者が別々の
 * 文字列リテラルを持つと、片方の改名で分類が無言で効かなくなるためである。
 */
export const OVERSIZED_BODY_REASON = 'oversized_body';

/**
 * `content-type` ヘッダから media type 部だけを取り出す。
 *
 * パラメータ（`; charset=utf-8`）を落とし、大文字小文字を無視できるよう小文字化する。
 *
 * @param value `content-type` ヘッダの値。
 * @returns 小文字化した media type（取り出せない場合は空文字）。
 */
function mediaTypeOf(value: string): string {
  return value.split(';')[0]?.trim().toLowerCase() ?? '';
}

/**
 * Content-Type が JSON 系（`application/json` / `*+json`）か判定する。
 *
 * 種別を問わずに本文をパースすると「JSON に見える別物」（HTML エラーページ等）を掴む。
 * パラメータ（`; charset=utf-8`）は落とし、media type だけを大文字小文字を無視して比較する。
 *
 * @param value `content-type` ヘッダの値（未設定なら `null`）。
 */
export function isJsonContentType(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  const mediaType = mediaTypeOf(value);
  return mediaType === 'application/json' || mediaType.endsWith('+json');
}

/** {@link isAllowedContentType} の任意設定。 */
export interface AllowedContentTypeOptions {
  /**
   * `content-type` ヘッダ欠落（`null`）を許容するか。既定は `false`（fail-closed）。
   *
   * ヘッダが無い応答は「何が返ってきたか宣言されていない」応答であり、取得先を攻撃者が選べる
   * 経路では `text/html` のエラーページと区別がつかない。したがって**既定は拒否**である。
   *
   * 欠落を許容してよいのは、本文自体が署名で真正性を持ち、かつプロファイルがヘッダ省略を
   * 許している経路（OpenID Federation の Entity Statement = JWT）に限る。その逸脱は
   * 判定の中に隠さず、**このフラグを立てる呼び出し側に書かせる**。経路ごとのポリシーが
   * 同名の述語の中に埋まっていると、片方だけが緩いことに気付けないためである。
   */
  readonly allowMissing?: boolean;
}

/**
 * Content-Type の media type が許容集合に含まれるか判定する。
 *
 * {@link isJsonContentType} は `*+json` という**接尾辞規則**を持つ JSON 系専用の述語で、
 * 集合として表現できない。DID Log（JSONL）のように「列挙した media type だけを受ける」経路は
 * こちらを使い、許容集合を呼び出し側から渡す。判定そのもの（パラメータ部の除去・大文字小文字の
 * 無視）は本モジュール 1 か所に置き、経路ごとに書き写さない。
 *
 * 許容集合の各要素は小文字の media type（`application/jsonl` 等）で渡すこと。
 *
 * @param value `content-type` ヘッダの値（未設定なら `null`）。
 * @param allowed 受理する media type の集合。
 * @param options ヘッダ欠落の扱い（{@link AllowedContentTypeOptions.allowMissing}）。
 * @returns 許容集合に含まれる media type なら `true`（`null` は `allowMissing` を立てた
 *   ときだけ `true`）。
 */
export function isAllowedContentType(
  value: string | null,
  allowed: readonly string[],
  options?: AllowedContentTypeOptions,
): boolean {
  if (value === null) {
    return options === undefined ? false : ownProperty<boolean>(options, 'allowMissing') === true;
  }
  return allowed.includes(mediaTypeOf(value));
}

/**
 * 本文の読み出し上限の調整（呼び出し側が総量予算で縛るための任意指定）。
 *
 * 既定は {@link MAX_DOCUMENT_BYTES}。`maxBytes` は既定より小さい値だけ効く（既定を超える上限は作れない）。
 */
export interface BodyLimitOptions {
  /** この呼び出しで受理する本文の最大バイト数（`MAX_DOCUMENT_BYTES` を上限に切り詰める）。 */
  readonly maxBytes?: number;
  /** 本文を最後まで読めたとき、その実バイト数で 1 回だけ呼ぶ（総量予算への計上用）。 */
  readonly onBytes?: (byteLength: number) => void;
}

/**
 * 読み終えた実バイト数を `onBytes` へ通知する。オプションは自身のプロパティだけを読む
 * （`Object.prototype` 汚染で計上フックが差し替わる・上限が緩むのを防ぐ）。
 */
function notifyBodyBytes(options: BodyLimitOptions | undefined, byteLength: number): void {
  if (options !== undefined) {
    nonObjectPrototypeProperty<BodyLimitOptions['onBytes']>(options, 'onBytes')?.(byteLength);
  }
}

/** 有効な本文上限（既定上限以下に切り詰め、非有限・負値は 0 として全拒否）。 */
export function effectiveBodyLimit(options?: BodyLimitOptions): number {
  const requested = options === undefined ? undefined : ownProperty<number>(options, 'maxBytes');
  if (requested === undefined) {
    return MAX_DOCUMENT_BYTES;
  }
  return Number.isFinite(requested) ? Math.max(0, Math.min(requested, MAX_DOCUMENT_BYTES)) : 0;
}

/**
 * `content-length` が上限超過を宣言しているか（本文を読む前の早期拒否）。
 *
 * 自己申告なので偽装され得るが、正直な巨大応答をストリームを開く前に落とせる。偽装への対処は
 * {@link readBodyWithinLimit} の実バイト数判定が担う。
 */
export function declaresOversizedBody(response: Response, options?: BodyLimitOptions): boolean {
  const raw = response.headers.get('content-length');
  if (raw === null) {
    return false;
  }
  const declared = Number.parseInt(raw, 10);
  return Number.isFinite(declared) && declared > effectiveBodyLimit(options);
}

/**
 * `body` を持たない応答から、上限を守りながら本文を取り出す（ストリーム不可時の代替）。
 *
 * 実 `fetch` の `Response` は常に `body` を持つが、この関数が受けるのは `Response` に構造的に
 * 適合するだけのオブジェクトでもあり得る。公開 DI 面（`createWallet({ …fetchImpl })` が受ける
 * `FetchLike`）は実装を型で縛らないので、`{ ok, headers, text() }` だけを持つホストアプリの実装が
 * ここに来る。**この経路は打ち切りではなく読み切りなので、上限は確保済みメモリに対してしか
 * 効かない**（ストリーム側のような途中打ち切りは原理的にできない）。
 *
 * そのうえで `arrayBuffer()` を `text()` より優先するのは、**上限超過を文字列化の前に落とす**ため
 * である。`text()` 経由だとバイト列に加えて UTF-16 文字列の分までメモリを取ってから捨てることに
 * なる。`arrayBuffer()` を持たないダブルのために `text()` も残す。
 */
async function readWholeBodyWithinLimit(
  response: Response,
  options?: BodyLimitOptions,
): Promise<Uint8Array | undefined> {
  const limit = effectiveBodyLimit(options);
  if (typeof response.arrayBuffer === 'function') {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > limit) {
      return undefined;
    }
    notifyBodyBytes(options, buffer.byteLength);
    return new Uint8Array(buffer);
  }
  const bytes = new TextEncoder().encode(await response.text());
  if (bytes.byteLength > limit) {
    return undefined;
  }
  notifyBodyBytes(options, bytes.byteLength);
  return bytes;
}

/**
 * 上限バイト数（{@link MAX_DOCUMENT_BYTES}）を守りながら応答本文を**バイト列のまま**読み出す。
 *
 * IPNS レコード（protobuf）のようにテキストへ復号すると壊れる本文のための読み出し。打ち切りの仕組みは
 * {@link readBodyWithinLimit} と同じ（`content-length` を偽装・省略されても実バイト数で打ち切る）。
 *
 * `body` を持たない応答は {@link readWholeBodyWithinLimit} のフォールバックへ倒す（読み切って
 * からの判定になる制約はそちらの docblock に記した）。実 `fetch` の `Response` は常に `body` を
 * 持つため、注入 fetch が実 `fetch` を包んでいる限り本番経路はストリーム側を通る。
 *
 * @returns 本文バイト列。上限超過なら `undefined`。
 */
export async function readBytesWithinLimit(
  response: Response,
  options?: BodyLimitOptions,
): Promise<Uint8Array | undefined> {
  const body = response.body;
  // `body` は「無い」ことを `null` でも `undefined` でも表し得る（後者は `Response` を模した
  // テストダブル）。`null` だけを見ると `undefined` の場合に `getReader` の参照で TypeError に
  // なり、呼び出し側では取得失敗と区別が付かない。読み出せるストリームかどうかで判定する。
  if (typeof body?.getReader !== 'function') {
    return await readWholeBodyWithinLimit(response, options);
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  const limit = effectiveBodyLimit(options);
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined) {
        continue;
      }
      total += value.byteLength;
      if (total > limit) {
        // 解放は最善努力にとどめ、`cancel()` の失敗で「上限超過」という結論を覆さない。await して
        // reject を伝播させると、呼び出し側は本文読み出しの例外を軒並みトランスポート失敗
        // （`fetch_failed` / `DID_NOT_FOUND` 等）へ正規化するため、超過を検出した当の経路で
        // 超過という情報が消える。
        // 意図的に捨てる: 失敗は接続が開いたまま残るだけで結論（上限超過）に影響しない。後始末の失敗なので
        // `onWarning` には流さない。
        void Promise.resolve(reader.cancel()).catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  notifyBodyBytes(options, total);
  return merged;
}

/**
 * 上限バイト数（{@link MAX_DOCUMENT_BYTES}）を守りながら応答本文をテキストとして読み出す。
 *
 * @returns 本文テキスト（UTF-8 復号）。上限超過なら `undefined`。
 */
export async function readBodyWithinLimit(
  response: Response,
  options?: BodyLimitOptions,
): Promise<string | undefined> {
  const bytes = await readBytesWithinLimit(response, options);
  return bytes === undefined ? undefined : new TextDecoder().decode(bytes);
}

/**
 * 読まずに捨てる応答本文を解放する（読み出し前に throw する経路の後始末）。
 *
 * 未消費の本文は undici でもブラウザでも接続とバッファ済みバイトを GC まで保持する。
 * 非 2xx / Content-Type 不正 / 宣言サイズ超過のように**本文を読まずに失敗へ倒す経路**は、
 * 「読まない」だけではソケットを生かしたまま残す。読まないなら明示的に `cancel()` する。
 *
 * 取得経路の `finally` から呼ぶことを想定しており、成功経路（読了済み）でも安全に通る:
 * 閉じた／エラー済みのストリームの `cancel()` は no-op である。読み出しの最中（`locked`）は
 * 読み手が自分で後始末するため触らない。後始末は最善努力なので、失敗しても元のエラーを覆さない。
 *
 * @param response 解放対象の応答（未取得なら `undefined`）。
 */
export function discardBody(response: Response | undefined): void {
  // `body` は「無い」ことを `null` でも `undefined` でも表し得る（後者は `Response` を模した
  // テストダブル）。解放できるストリームかどうかで判定する。
  const body = response?.body;
  if (typeof body?.cancel !== 'function' || body.locked === true) {
    return;
  }
  try {
    // 意図的に捨てる（理由は上の `reader.cancel()` と同じ）。
    void Promise.resolve(body.cancel()).catch(() => undefined);
  } catch {
    // 解放できない実装／ダブルでも、呼び出し元が投げているエラーを覆わない。
  }
}
