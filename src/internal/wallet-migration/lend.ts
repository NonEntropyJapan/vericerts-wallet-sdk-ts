/**
 * W2W 一時共有（Lend）プロトコル。
 *
 * 貸主の署名を添えたトークンで一時共有する。期限切れのトークンを使うと `W2W_LEND_EXPIRED` となる。
 *
 * 家族タブレット等に期限付きで VC を共有する。Lender が lend-request に署名し、借主は
 * `redeemLend` で期限内かつ署名有効なトークンのみ引き換えられる。期限切れは 4034。
 *
 * セキュリティ上の注意:
 * - 秘密（VC 平文 / 鍵）は例外に含めない。署名検証失敗・期限切れは 4034 に正規化する。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { parseIsoDateOrDateTimeMs, parseIsoDateTimeMs } from '../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { PublicKeyJwk } from '../identity/did.js';
import { jwkToUncompressedPublicKey } from '../identity/jwt/jwk-key.js';
import { verifyP256 } from '../keymanager/signer.js';
import { assertTimerIntervalMs } from '../primitives/option-guard.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import {
  type BackupSigner,
  type CreateLendDependencies,
  DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS,
  type LendToken,
  W2W_SIGNER_JWK_OPTIONS,
} from './types.js';

const textEncoder = new TextEncoder();

/**
 * Lend トークンの署名対象（`lender_signature` を除いた本文）を決定論的に直列化し digest を返す。
 *
 * @param token 署名対象（`lender_signature` を除く）。
 * @returns 署名対象の SHA-256 digest（32 バイト）。
 */
function lendDigest(token: Omit<LendToken, 'lender_signature'>): Uint8Array {
  return sha256(textEncoder.encode(JSON.stringify(token)));
}

/**
 * Lend トークンを作成する。Lender が本文に ES256 署名する。
 *
 * @param vcIds 貸し出す VC の ID 群。
 * @param validUntil 有効期限（ISO 8601）。到達時に自動失効。
 * @param recipientDID 借主の DID。
 * @param lender 貸主の署名者（`keyId` を lender_did として使う）と署名関数。
 * @param opts 提示許可タイプなど。
 * @param deps 依存注入（ID / 時刻）。
 * @returns 署名済み Lend トークン。
 * @throws valid_until が過去の場合（VericertsError、code `4034`）。
 */
export function createLend(
  vcIds: readonly string[],
  validUntil: string,
  recipientDID: string,
  lender: { readonly did: string; readonly signer: BackupSigner },
  opts: { readonly allowPresentationTypes?: readonly string[] } = {},
  deps: CreateLendDependencies = {},
): LendToken {
  // 任意の依存注入・オプションは自身のプロパティに限って読む。ここで組み立てた
  // `unsigned` は Lender の ES256 署名対象になるため、継承値を拾うと、その項目を**省略した**
  // 正当な貸出でも汚染値が**署名済み Lend トークン**に載る:
  // - `now`: 期限切れ判定（4034）が攻撃者の選んだ時刻で行われる。
  // - `generateId`: トークン ID が攻撃者の関数由来になり、一意性・追跡可能性が壊れる。
  // - `allowPresentationTypes`: 貸出時に許可していない提示タイプが署名済みトークンに載る。
  const createNowFn = nonObjectPrototypeProperty<() => number>(deps, 'now');
  const now = createNowFn !== undefined ? createNowFn() : Date.now();
  const expiryMs = parseIsoDateTimeMs(validUntil);
  if (!Number.isFinite(expiryMs) || !Number.isFinite(now) || expiryMs <= now) {
    // 過去 / 不正な期限は貸出できない。期限切れ相当として 4034 に正規化する。
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  const generateId = nonObjectPrototypeProperty<() => string>(deps, 'generateId');
  const id = generateId !== undefined ? generateId() : crypto.randomUUID();
  const allowPresentationTypes = ownProperty<readonly string[]>(opts, 'allowPresentationTypes');
  const unsigned: Omit<LendToken, 'lender_signature'> = {
    id,
    vc_ids: [...vcIds],
    valid_until: validUntil,
    ...(allowPresentationTypes !== undefined
      ? { allow_presentation_types: [...allowPresentationTypes] }
      : {}),
    lender_did: lender.did,
    recipient_did: recipientDID,
  };
  const signature = lender.signer.sign(lendDigest(unsigned));
  return { ...unsigned, lender_signature: base64urlnopad.encode(signature) };
}

/**
 * Lend トークンの署名を検証する（lender の公開鍵で ES256 検証）。
 *
 * @param token 検証対象の Lend トークン。
 * @param lenderPublicKeyJwk 貸主の EC 公開鍵 JWK（`crv: 'P-256'`）。
 * @returns 署名が有効なら `true`。
 */
export function verifyLendSignature(token: LendToken, lenderPublicKeyJwk: PublicKeyJwk): boolean {
  let signature: Uint8Array;
  try {
    signature = base64urlnopad.decode(token.lender_signature);
  } catch {
    return false;
  }
  const { lender_signature: _sig, ...unsigned } = token;
  const publicKey = jwkToUncompressedPublicKey(lenderPublicKeyJwk, W2W_SIGNER_JWK_OPTIONS);
  // JWS ではないため ES256 の high-S 受理の対象外。W2W の署名契約は low-S 固定
  // のため `allowHighS: false` を明示する。
  return verifyP256(lendDigest(unsigned), signature, publicKey, { allowHighS: false });
}

/** `redeemLend` の依存注入。 */
export interface RedeemLendDependencies {
  /** 貸主の公開鍵 JWK（署名検証用）。 */
  readonly lenderPublicKeyJwk: PublicKeyJwk;
  /** 現在時刻（エポックミリ秒。テスト注入用）。省略時は `Date.now()`。 */
  readonly now?: () => number;
  /**
   * 失効済みトークン ID かを判定する（`revokeLend` で失効したものを反映）。
   * `false` を返したときのみ未失効として扱い、`true` を含む `false` 以外の戻り値は期限切れ相当（4034）
   * とする（fail-closed）。`redeemLend` は同期関数のため **Promise を返す（async の）関数は
   * 失効判定を待てず、未失効とみなさずに 4034 で拒否する**。`revokeLend` の永続化先が非同期でも、
   * 失効済み ID はメモリ上の台帳へ反映して同期関数で引くこと。省略時は失効チェックしない。
   */
  readonly isRevoked?: (tokenId: string) => boolean;
}

/**
 * Lend トークンを引き換え、共有された VC ID 群を返す。
 *
 * 期限切れ・署名不正・失効済みは 4034（W2W_LEND_EXPIRED）に正規化する。返すのは VC ID の
 * 配列で、実 VC の取得（提示時の委任チェーン検証含む）は呼び出し側が担う。
 *
 * @param token 引き換え対象の Lend トークン。
 * @param deps 依存注入（貸主公開鍵 / 時刻 / 失効判定）。
 * @returns 共有された VC ID 群。
 * @throws 期限切れ / 署名不正 / 失効済み / `isRevoked` が `false` 以外（Promise 含む）を返した場合
 *         （VericertsError、code `4034`）。
 */
export function redeemLend(token: LendToken, deps: RedeemLendDependencies): readonly string[] {
  // 引き換え側も同じく own 限定で読む。継承した `now` は期限切れの Lend トークンを
  // 引き換え可能にし、継承した `isRevoked` は失効判定を攻撃者の関数へ委譲する。
  const redeemNowFn = nonObjectPrototypeProperty<() => number>(deps, 'now');
  const now = redeemNowFn !== undefined ? redeemNowFn() : Date.now();
  // **発行済みトークンの判定には日付のみ（`YYYY-MM-DD`）も受け付ける。** 新規発行
  // （`createLend`）は厳格な形式だけを通すが、以前に発行されて保存されているトークンまで
  // 解釈できなくすると、期限内なのに引き換えられなくなる。日付のみは ECMAScript 上 UTC 固定で
  // 実行環境の TZ に依存しないため、オフセット無しの**日時**（TZ で値が変わる）とは別に扱える。
  const expiryMs = parseIsoDateOrDateTimeMs(token.valid_until);
  if (!Number.isFinite(expiryMs) || !Number.isFinite(now) || expiryMs <= now) {
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  // 関数値の DI は own 限定では読めない。`isRevoked` を prototype メソッドで実装した正当な
  // クラスベース DI が「未指定」と判定され、**失効検査が無言でスキップ**される（fail-open）。
  // `Object.prototype` 由来だけを弾く `nonObjectPrototypeProperty` を使う（同ファイルの
  // `revokeLend` の `markRevoked` と扱いを揃える）。
  const isRevoked = nonObjectPrototypeProperty<(id: string) => boolean>(deps, 'isRevoked');
  if (isRevoked !== undefined && typeof isRevoked !== 'function') {
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  if (isRevoked !== undefined) {
    const revoked: unknown = isRevoked(token.id);
    // 失効の根拠は台帳の引き結果であり、`false` 以外（`true` / Promise / undefined / truthy 値）は
    // 未失効と断定できないため拒否する。async 関数の戻り値（Promise）が `=== true` を満たさず
    // 失効済みトークンを通す fail-open を避ける。reject する Promise は未処理にしない。
    if (revoked !== false) {
      if (revoked instanceof Promise) {
        // 意図的に捨てる: 結論は直下の `W2W_LEND_EXPIRED` で決まっており、Promise の reject 理由は使わない。
        revoked.catch(() => undefined);
      }
      throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
    }
  }
  // 貸主の検証鍵も同一関数内で読み方を揃える（鍵だけ鎖経由だと汚染鍵で署名検証が通る）。
  const lenderPublicKeyJwk = nonObjectPrototypeProperty<
    RedeemLendDependencies['lenderPublicKeyJwk']
  >(deps, 'lenderPublicKeyJwk');
  if (lenderPublicKeyJwk === null || typeof lenderPublicKeyJwk !== 'object') {
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  if (!verifyLendSignature(token, lenderPublicKeyJwk)) {
    // 署名不正は改ざん相当。Lend の失効/無効として 4034 に正規化する。
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  return [...token.vc_ids];
}

/** `revokeLend` の依存注入。 */
export interface RevokeLendDependencies {
  /** トークン失効を永続化する（Dashboard への通知を含む）。 */
  readonly markRevoked: (tokenId: string) => void | Promise<void>;
}

/**
 * Lend トークンを失効させる。期限前でも貸主が明示的に取り消せる。
 *
 * @param tokenId 失効させるトークン ID。
 * @param deps 依存注入（失効の永続化）。
 */
export async function revokeLend(tokenId: string, deps: RevokeLendDependencies): Promise<void> {
  // 失効の永続化先も自身のプロパティに限って読む。継承値を拾うと、`markRevoked` を
  // 渡し忘れた呼び出しが攻撃者の関数を呼んで**何も失効させずに正常終了**し、貸主には失効済みに
  // 見えるまま Lend トークンが有効であり続ける。永続化手段が無ければ失敗として送出する。
  const markRevoked = nonObjectPrototypeProperty<RevokeLendDependencies['markRevoked']>(
    deps,
    'markRevoked',
  );
  if (typeof markRevoked !== 'function') {
    throw new VericertsError(ErrorCodes.W2W_LEND_EXPIRED);
  }
  await markRevoked(tokenId);
}

/** `expireOverdueLends` の依存注入。`revokeLend` の依存に `now` を加える。 */
export interface ExpireOverdueLendsDependencies extends RevokeLendDependencies {
  /** 現在時刻（エポックミリ秒。テスト注入用）。省略時は `Date.now()`。 */
  readonly now?: () => number;
}

/**
 * `tokens` のうち `valid_until` を過ぎたものを検知し、`revokeLend` で失効させる。
 *
 * @param tokens 監視対象の Lend トークン群。
 * @param deps 依存注入（失効の永続化 / 時刻）。
 * @returns 失効させたトークン ID 群（呼び出し側のログ・アサーション用）。
 */
export async function expireOverdueLends(
  tokens: readonly LendToken[],
  deps: ExpireOverdueLendsDependencies,
): Promise<readonly string[]> {
  // `now` は関数値の DI。`createLend` / `redeemLend` と同じく `Object.prototype` 由来だけを弾く。
  const nowFn = nonObjectPrototypeProperty<() => number>(deps, 'now');
  const now = nowFn !== undefined ? nowFn() : Date.now();
  const expiredIds: string[] = [];
  for (const token of tokens) {
    const expiryMs = parseIsoDateOrDateTimeMs(token.valid_until);
    // **解釈できない `valid_until` では失効させない。** 失効は `revokeLend` で永続化され
    // 取り消せず、`valid_until` は署名対象なので後から直せない。読めない値を「期限切れ」と断じると、
    // パーサを厳しくした更新だけで期限内のトークンが不可逆に死ぬ。
    //
    // fail-closed は引き換えの入口で保たれる: `redeemLend` は解釈できない `valid_until` を
    // `4034 W2W_LEND_EXPIRED` で拒否する。能動的な掃除は「期限切れだと証明できるもの」だけに限り、
    // 証明できないものは使わせないだけに留める（取り消せる側へ倒す）。
    if (!Number.isFinite(expiryMs) || !Number.isFinite(now)) continue;
    if (expiryMs <= now) {
      await revokeLend(token.id, deps);
      expiredIds.push(token.id);
    }
  }
  return expiredIds;
}

/** `scheduleLendExpiryChecks` の依存注入。 */
export interface ScheduleLendExpiryChecksDependencies extends ExpireOverdueLendsDependencies {
  /**
   * 定期実行のスケジューラ（テスト注入用）。停止関数を返す。
   * 省略時は `setInterval` / `clearInterval`。
   */
  readonly schedule?: (task: () => void, intervalMs: number) => () => void;
  /** チェック間隔（ミリ秒）。省略時は {@link DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS}。 */
  readonly intervalMs?: number;
  /** チェック中の例外の通知先。省略時は握りつぶして次回チェックでの回復を許す。 */
  readonly onError?: (error: unknown) => void;
}

/**
 * Lend トークンの期限監視を定期実行し、期限到達分を `expireOverdueLends` で失効させる。
 *
 * @param getTokens 監視対象トークンの取得（毎チェック時に呼ぶ。非同期可）。
 * @param deps 依存注入（失効の永続化 / 時刻 / スケジューラ / 間隔 / エラー通知）。
 * @returns 監視を停止する関数。
 * @throws `intervalMs` が 1 以上 2147483647 以下の有限数でない場合（`RangeError`）。
 */
export function scheduleLendExpiryChecks(
  getTokens: () => readonly LendToken[] | Promise<readonly LendToken[]>,
  deps: ScheduleLendExpiryChecksDependencies,
): () => void {
  // `intervalMs` は純データ。鎖読みだと、未指定の呼び出しが汚染値の監視間隔を拾う。
  // NaN・負値・0・タイマー上限超過は `setInterval` で約 1ms の高頻度ループになり tick が重複するため拒否する。
  const intervalMs = assertTimerIntervalMs(
    'intervalMs',
    ownProperty<number>(deps, 'intervalMs') ?? DEFAULT_LEND_EXPIRY_CHECK_INTERVAL_MS,
  );
  // 前回の tick が未完了の間は次の tick を開始しない（遅いストアで実行が重なり二重失効するのを防ぐ）。
  let running = false;
  const tick = (): void => {
    if (running) return;
    running = true;
    void (async () => {
      try {
        await expireOverdueLends(await getTokens(), deps);
      } catch (error) {
        // `onError` は DI 関数。own 限定だとクラス DI のプロトタイプメソッドを弾く。
        const onError = nonObjectPrototypeProperty<(e: unknown) => void>(deps, 'onError');
        if (typeof onError === 'function') {
          onError(error);
        }
      } finally {
        running = false;
      }
    })();
  };
  const schedule = nonObjectPrototypeProperty<ScheduleLendExpiryChecksDependencies['schedule']>(
    deps,
    'schedule',
  );
  // レシーバは `deps` に束ね直す。裸で呼ぶと `this` 参照つきクラス DI が壊れる。
  return typeof schedule === 'function'
    ? schedule.call(deps, tick, intervalMs)
    : ((): (() => void) => {
        const handle = setInterval(tick, intervalMs);
        return () => clearInterval(handle);
      })();
}
