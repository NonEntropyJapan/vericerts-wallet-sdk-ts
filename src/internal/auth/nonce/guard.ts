/**
 * KB-JWT 検証経路への replay 検知の接続。
 *
 * 同期 API `verifySdJwt` の検証に、seen-nonces cache による nonce の一回限りの消費を加える。
 *
 * 検査順序は「バインディング（`aud`）→ 暗号検証 → 時刻 → nonce 消費」。nonce の消費を最後に
 * 置くのは、署名不正な提示で正規の nonce を焼き潰す DoS を防ぐため。`aud` の照合を暗号検証より
 * 前に置くのは、`verifySdJwt` が `requireKeyBinding: true` に `audience` の指定を要求するように
 * なったためで、本ラッパは委譲前に自前で照合して不一致を 4012 のまま保つ。署名前に
 * 読む値を信頼しないことの根拠は当該箇所のコメントを参照。
 *
 * `nonceContext` は入口で `snapshotNonceContext` によりデータスナップショットへ畳み、以降は照合・
 * 窓選択・`checkAndUse` への受け渡しまで同一スナップショットを使う（理由は `context-snapshot.ts`）。
 */

import { parseSdJwt } from '../../credential/sdjwt/sdjwt.js';
import {
  type VerifiedSdJwt,
  type VerifySdJwtOptions,
  verifySdJwt,
} from '../../credential/sdjwt/verify.js';
import { decodeCompactJwsOrThrow } from '../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { assertBindingMatches, bindingValueForFlow } from './context.js';
import { snapshotNonceContext } from './context-snapshot.js';
import { assertWellFormedNonce } from './generate.js';
import { assertWithinReplayWindow } from './replay-window.js';
import type { NonceContext, NonceFlow, NonceStore } from './types.js';

/** `verifySdJwtWithReplayGuard` のオプション。 */
export interface ReplayGuardOptions extends VerifySdJwtOptions {
  /** 消費記録を保持する `NonceStore`。 */
  readonly nonceStore: NonceStore;
  /** nonce の発行コンテキスト。`aud` の照合対象もここから取る。 */
  readonly nonceContext: NonceContext;
  /** Verifier が発行し KB-JWT に載っているはずの nonce。 */
  readonly nonce: string;
  /** replay window（秒）の上書き。既定は flow によって決まる。 */
  readonly replayWindowSeconds?: number;
  /** 初見 nonce を記録する際の保持期間（ms）。既定は flow ごとの TTL。 */
  readonly nonceTtlMs?: number;
}

/**
 * KB-JWT 付き SD-JWT VC を検証し、nonce を 1 回だけ消費する。
 *
 * 照合対象は `nonceContext` の束縛値で、KB-JWT の実測 `aud` と定数時間比較する。
 * 不一致は 3012 ではなく 4012 になる。
 *
 * `audience` を併せて指定した場合は `nonceContext` の束縛値と**一致必須**で、不一致なら
 * 4012 を投げる。黙って捨てると、`nonceStore` / `nonceContext` を足した瞬間に
 * `audience` の検査対象が束縛値へすり替わる（silent behavior change）ため。
 *
 * `opts` と KB-JWT payload の読み取りは関数全体で own 限定に揃える。省略された
 * 入力に `Object.prototype` の継承値が入り込むと、攻撃者が選んだ nonce / 束縛値 / ストアで
 * 「検証済み」を作れてしまうため、必須入力が own 読みで得られない場合は fail-closed に落とす。
 *
 * @param sdJwt KB-JWT を含む SD-JWT VC 提示。
 * @param opts 検証鍵・nonce・コンテキスト・`NonceStore` 等。
 * @returns 検証済みクレーム。
 * @throws 4013 nonce 形式不正・欠落 / 4012 バインディング不一致（`audience` 併用時の不整合・
 *         `nonceContext` 欠落を含む）/ 4014 replay-window 外 / 4010 nonce 再利用・
 *         `nonceStore` 欠落 / 4011 nonce 期限切れ / 3012 KB-JWT 不整合・構造不正。
 */
export async function verifySdJwtWithReplayGuard(
  sdJwt: string,
  opts: ReplayGuardOptions,
): Promise<VerifiedSdJwt> {
  // 必須入力も自身のプロパティに限って読む。省略した呼び出しで継承値を拾うと、
  // 攻撃者が仕込んだ nonce が「Verifier が発行した nonce」として消費されるうえ、KB-JWT 側の
  // nonce 照合も `verifySdJwt` が own 限定で読む結果 undefined になって丸ごと省略される。
  const nonce = ownProperty<string>(opts, 'nonce');
  assertWellFormedNonce(nonce);

  // `nonceContext` は束縛値と拒否リストのキー空間の両方を決める。継承値を拾うと攻撃者が
  // 選んだ束縛値・名前空間で検査したことになり、`aud` 照合もリプレイ検知も無意味になる。
  const nonceContext = ownProperty<NonceContext>(opts, 'nonceContext');
  if (nonceContext === undefined) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // ここでコンテキストを own 限定のデータスナップショットへ畳み、以降は（照合・窓選択・
  // キー組み立て・下層 `checkAndUse` への受け渡しまで）**このスナップショットだけ**を使う。
  // 生の `nonceContext` を下層へ渡すと store 層が `flow` / 束縛値を読み直し、層をまたいで
  // `flow` が分裂すると照合済みの flow とは別のキー空間へ消費記録が書かれて同一 nonce を
  // 2 回消費できる（`context-snapshot.ts` の JSDoc）。
  const ctx = snapshotNonceContext(nonceContext);
  // `flow` を欠くコンテキストでは束縛値も既定ウィンドウも引けない。継承値で補うと攻撃者が
  // flow を選べるので、own 読みできなければ束縛不成立として閉じる。
  const flow = ownProperty<NonceFlow>(ctx, 'flow');
  if (flow === undefined) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }

  // `nonceStore` は DI 依存で、`class MemoryNonceStore { async checkAndUse() {} }` のように
  // プロトタイプメソッドで実装するのが正当なため own 限定では読めない（own 化しすぎると
  // 消費記録が無言でスキップされる）。`Object.prototype` 由来だけを弾いたうえで、`checkAndUse`
  // が関数でなければ「消費を証明できない」として fail-closed に落とす。
  const nonceStore = nonObjectPrototypeProperty<NonceStore>(opts, 'nonceStore');
  const checkAndUse =
    nonceStore === undefined
      ? undefined
      : nonObjectPrototypeProperty<NonceStore['checkAndUse']>(nonceStore, 'checkAndUse');
  if (nonceStore === undefined || typeof checkAndUse !== 'function') {
    throw new VericertsError(ErrorCodes.REPLAY_DETECTED);
  }

  const parts = parseSdJwt(sdJwt);
  const keyBinding = ownProperty<string>(parts, 'keyBinding');
  if (keyBinding === undefined) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }

  // aud の照合は本ラッパが 4012 として扱うため（3012 に潰さない）、`verifySdJwt` へ委譲する
  // **前に**自前で済ませる。`requireKeyBinding: true` は `audience` の指定を要求するため
  // 委譲時に `audience: undefined` を渡し続けることはできない。
  //
  // ここで読む payload はまだ署名検証を経ていないが、値をそのまま信頼はしない。実測 `aud` は
  // 直後に `nonceContext` の束縛値と定数時間で照合され、一致した場合しか先へ進まない。委譲先の
  // `verifySdJwt` は KB-JWT 署名を検証したうえで同じ束縛値と `aud` を再照合するため、署名前に
  // 読んだ値が検証結果に持ち込まれることはない。構造不正は委譲先と同じ 3012 へ正規化する。
  //
  // 副作用として、束縛値の一致 / 不一致が**署名検証なしで**判別できる（任意のゴミトークンで
  // 4012 か否かを引ける）。これは許容する。束縛値は `aud` = Verifier の `client_id` で公開値で
  // あり秘匿値ではないため oracle としての価値が無い（`nonce` は `opts` 由来で攻撃者は触れない）。
  // なお複合失敗時の優先順位は変わる: Issuer 署名不正 ＋ `aud` 不一致は従来 3010 だったが 4012 に、
  // Issuer 署名不正 ＋ KB-JWT 構造不正は従来 3010 だったが 3012 になる（いずれも fail-closed 側で、
  // 単独失敗時のコードは不変）。
  //
  // KB-JWT payload は `JSON.parse` 由来の生オブジェクト。`aud` を鎖読みすると、**`aud` を
  // 持たない KB-JWT** が `Object.prototype.aud` の汚染値を「実測 aud」として採用され、
  // バインディング検査が一致に化ける。
  const payload = decodeCompactJwsOrThrow(keyBinding, ErrorCodes.HOLDER_BIND_MISMATCH).payload;
  const aud = ownProperty<unknown>(payload, 'aud');
  if (typeof aud !== 'string') {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // 束縛値も `flow` もスナップショットから読む（値はデータプロパティに畳まれているので、
  // 何度読んでも同じ値が返る）。`flow` は上で 1 度読んだ結果をそのまま渡し、**束縛メンバの
  // 選択と replay-window の既定窓選択の双方に同じ値を使う**（`bindingValueOf` は内部で
  // `flow` を読み直すため使わない。単一読み（read-once）規則）。
  const expectedAudience = bindingValueForFlow(ctx, flow);
  // 空の束縛値は Verifier を識別できず「この提示宛か」を判定できない。委譲先が同じ理由で 3012
  // にするより前に、本ラッパ自身の失敗面である 4012 で閉じて経路を混ぜない。
  // 空文字判定は SDK 内の単一の共有ヘルパで行う（層ごとに複製しない）。
  if (!isNonEmptyString(expectedAudience)) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // 呼び出し側の `audience` も束縛値と一致必須。一致する限り実測 `aud` の照合が
  // 同じ値を検査するため、`audience` 検査は失われずに 4012 経路へ吸収される。
  // 未指定時に継承値を拾うと、正当な提示が汚染値との照合で 4012 に落とされる。
  assertBindingMatches(expectedAudience, ownProperty<string>(opts, 'audience'));
  assertBindingMatches(expectedAudience, aud);

  // 期待値には（実測 `aud` ではなく）束縛値そのものを渡す。実測値を期待値に流用すると照合が
  // 自明に成立してしまうため、`nonceContext` 由来の値を委譲先でも期待値として使う。
  const verified = verifySdJwt(sdJwt, {
    ...opts,
    audience: expectedAudience,
    nonce,
    requireKeyBinding: true,
  });

  // 任意プロパティは自身のプロパティに限って読む。ここで継承値を**新しい
  // オブジェクトリテラルへ詰め直す**と own プロパティに化け、`assertWithinReplayWindow` 側の
  // own 限定読み取りが無効化される（`own-property.ts` の JSDoc が警告する失敗様式）。
  // 継承した `replayWindowSeconds`（例 `Infinity`）はリプレイ窓を丸ごと無効化し、
  // 継承した `nowSeconds` は攻撃者が選んだ「現在時刻」で `iat` を評価させる。
  const guardNowSeconds = ownProperty<number>(opts, 'nowSeconds');
  const guardWindowSeconds = ownProperty<number>(opts, 'replayWindowSeconds');
  const windowOpts =
    guardWindowSeconds === undefined
      ? { nowSeconds: guardNowSeconds }
      : { nowSeconds: guardNowSeconds, windowSeconds: guardWindowSeconds };
  // `iat` も own 限定で読む。鎖読みだと `iat` を持たない KB-JWT が汚染値で「窓内」に化ける。
  assertWithinReplayWindow(ownProperty<unknown>(payload, 'iat'), flow, windowOpts);

  // 検証済みの `checkAndUse` をそのまま呼ぶ（`this` はストア本体に束ねる）。再度
  // `nonceStore.checkAndUse` と書くと検証した値と呼ぶ値がずれ得る。`nonceTtlMs` も同じ理由で
  // 1 度だけ読んで変数に置く（存在判定と値取得で 2 度読むと両者がずれ得る）。
  const nonceTtlMs = ownProperty<number>(opts, 'nonceTtlMs');
  await checkAndUse.call(nonceStore, nonce, ctx, {
    binding: aud,
    ...(nonceTtlMs === undefined ? {} : { ttlMs: nonceTtlMs }),
  });

  return verified;
}
