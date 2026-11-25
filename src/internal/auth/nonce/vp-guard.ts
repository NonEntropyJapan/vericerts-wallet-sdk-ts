/**
 * JWT-VP 検証経路への replay 検知の接続。
 *
 * `verifyPresentation` に seen-nonces cache を組み合わせ、同じ nonce の再使用を 4010 `REPLAY_DETECTED` で拒否する。
 * KB-JWT に対する `verifySdJwtWithReplayGuard` に対応する非同期ラッパ。
 *
 * 検査順序は「暗号検証 → バインディング → 時刻 → nonce 消費 → 内包 VC 検証」。
 * nonce の消費を最後から 2 番目に置くのは、署名不正な提示で正規の nonce を消費されることを
 * 防ぐため。内包 VC の検証をさらにその後ろに置くのは、そこへ中継する実効バインド値（束縛照合を
 * 終えた実測 `aud` と本ラッパの `nonce`）がバインディング検査を通るまで確定しないためで、内包 VC
 * の成否は nonce 消費の可否に影響しない。
 *
 * `nonceContext` は入口で `snapshotNonceContext` によりデータスナップショットへ畳み、以降は照合・
 * 窓選択・`checkAndUse` への受け渡しまで同一スナップショットを使う（`guard.ts` と同じ形。理由は
 * `context-snapshot.ts`）。束縛値は `bindingValueForFlow` で 1 度だけ読み、`assertBindingMatches` で
 * 2 度照合する（`assertBinding` を 2 回呼ぶと束縛値も 2 回読まれて TOCTOU になる）。空文字の束縛値は
 * Verifier を識別できないため 4012 で閉じ、KB-JWT 経路と失敗面を対称に保つ。
 */

import { resolvePresentationVerificationFields } from '../../credential/presentation/credential-results.js';
import {
  type VerifiedPresentation,
  type VerifiedPresentationClaims,
  type VerifyPresentationOptions,
  verifyPresentationClaims,
} from '../../credential/presentation/presentation.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString } from '../../prototype-safety/non-empty-string.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { assertBindingMatches, bindingValueForFlow } from './context.js';
import { snapshotNonceContext } from './context-snapshot.js';
import { assertWellFormedNonce } from './generate.js';
import { assertWithinReplayWindow } from './replay-window.js';
import type { NonceContext, NonceFlow, NonceStore } from './types.js';

/**
 * `verifyPresentationWithReplayGuard` のオプション。
 *
 * `expectedNonce` / `allowUnbound` は**指定できない**（型レベルで `Omit` している）。この 2 つは
 * ラッパが `nonce` を唯一の nonce 入力として制御するため、受け取っても黙って捨てるほかなく、
 * 呼び出し側の指定が無視されたことに気付けない（silent behavior change）。`expectedAudience` は
 * 指定可能で、`nonceContext` の束縛値と一致必須。
 */
export interface PresentationReplayGuardOptions
  extends Omit<VerifyPresentationOptions, 'expectedNonce' | 'allowUnbound'> {
  /** 消費記録を保持する `NonceStore`。 */
  readonly nonceStore: NonceStore;
  /** nonce の発行コンテキスト。`aud` の照合対象もここから取る。 */
  readonly nonceContext: NonceContext;
  /** Verifier が発行し JWT-VP payload の `nonce` に載っているはずの nonce。 */
  readonly nonce: string;
  /** replay window（秒）の上書き。既定は flow によって決まる。 */
  readonly replayWindowSeconds?: number;
  /** 初見 nonce を記録する際の保持期間（ms）。既定は flow ごとの TTL。 */
  readonly nonceTtlMs?: number;
}

/**
 * replay ガードの検査を終えた中間結果（内包 VC は未検証）。`verifyPresentationWithReplayGuardClaims`
 * の戻り値で、内包 VC の評価に必要な**実効バインド値**を確定した形で持ち回るための内部型。
 */
export interface GuardedPresentationClaims extends VerifiedPresentationClaims {
  /** `nonceContext` の束縛値と照合済みの実測 `aud`（実効 audience）。 */
  readonly audience: string;
  /** 本ラッパが唯一の nonce 入力として扱い、消費まで済ませた値（実効 nonce）。 */
  readonly nonce: string;
}

/**
 * JWT-VP を検証し、nonce を 1 回だけ消費する。
 *
 * 照合対象は `nonceContext` の束縛値で、JWT-VP payload の実測 `aud` と定数時間比較する。
 * 不一致は 3012 ではなく 4012 になる。
 *
 * `expectedAudience` を併せて指定した場合は `nonceContext` の束縛値と**一致必須**で、不一致なら
 * 4012 を投げる。黙って捨てると、`nonceStore` / `nonceContext` を足した瞬間に
 * `expectedAudience` の検査対象が束縛値へすり替わる（silent behavior change）ため。
 *
 * nonce の入力は `nonce` ただ 1 つで、`expectedNonce` / `allowUnbound` は型レベルで指定できない
 * （`PresentationReplayGuardOptions`）。受け取れてしまうと本ラッパの上書きで黙って捨てられるため。
 *
 * `iat` は replay window で過去・未来の双方向に判定する（`verifyPresentation` 単体の
 * クロックスキュー評価は未来方向のみ）。`iat` を持たない VP は本ラッパでは 4014 になる。
 *
 * 戻り値の `credentialResults` は、束縛照合を終えた**実効 `aud`** と本ラッパの `nonce` で
 * 組み立てる（`withEffectiveBinding`）。VP レベルの検証には内包 VC を検証しない
 * `verifyPresentationClaims` を使うため、内包 VC の暗号検証と `credentialKey` コールバックは
 * **1 エントリにつき 1 回だけ**走る（実効 `aud` は VP 署名の検証後にしか確定しないため、
 * `verifyPresentation` をそのまま呼ぶとその結果を捨てて評価し直すことになる）。
 *
 * `opts` と payload の読み取りは関数全体で own 限定に揃える。省略された入力に
 * `Object.prototype` の継承値が入り込むと、攻撃者が選んだ nonce / 束縛値 / ストアで
 * 「検証済み」を作れてしまうため、必須入力が own 読みで得られない場合は fail-closed に落とす。
 *
 * @param jwt 検証対象のコンパクト JWT-VP 文字列。
 * @param opts 検証鍵・nonce・コンテキスト・`NonceStore` 等。
 * @returns 検証済みヘッダ・ペイロード・VP（`verifyPresentation` の戻り値そのまま）。
 * @throws 4013 nonce 形式不正・欠落 / 4012 バインディング不一致（`expectedAudience` 併用時の
 *         不整合・`aud` 欠落・`nonceContext` 欠落・束縛値が空文字を含む）/ 4014 `iat` が replay-window 外または
 *         欠落 / 4010 nonce 再利用・`nonceStore` 欠落 / 4011 nonce 期限切れ /
 *         3012 提示バインド不整合（nonce 不一致等）。
 */
export async function verifyPresentationWithReplayGuard(
  jwt: string,
  opts: PresentationReplayGuardOptions,
): Promise<VerifiedPresentation> {
  const guarded = await verifyPresentationWithReplayGuardClaims(jwt, opts);
  return withEffectiveBinding(guarded, opts);
}

/**
 * replay ガードの検査だけを行い、**内包 VC は検証しない**内部経路。
 *
 * `verifyPresentationWithReplayGuard` の実体で、`credentialResults` を組み立てない点だけが異なる。
 * **公開 API ではない**（`exports/` から出していない）。
 *
 * Wallet ファサードはプリミティブの `credentialResults` を使えない（発行者鍵を DID 解決で補完して
 * から組み直す必要があり、その解決は非同期で `credentialKey` へ渡せない）。公開ラッパを呼ぶと
 * 捨てるだけの内包 VC 検証が 1 パス余計に走るため、ファサードは本関数を直接呼ぶ。
 *
 * @param jwt 検証対象のコンパクト JWT-VP 文字列。
 * @param opts `verifyPresentationWithReplayGuard` と同じオプション。
 * @returns VP レベルの検証結果と、束縛照合を終えた実効 `aud` / 消費した `nonce`。
 * @throws `verifyPresentationWithReplayGuard` と同じ。
 */
export async function verifyPresentationWithReplayGuardClaims(
  jwt: string,
  opts: PresentationReplayGuardOptions,
): Promise<GuardedPresentationClaims> {
  // 必須入力も自身のプロパティに限って読む。継承した `nonce` を拾うと、
  // `expectedNonce` は own 読みで undefined のまま `allowUnbound: true` で照合が省略され、
  // かつ攻撃者が仕込んだ nonce が消費される（nonce 照合が丸ごと消える fail-open）。
  const nonce = ownProperty<string>(opts, 'nonce');
  assertWellFormedNonce(nonce);

  // `nonceContext` は束縛値と拒否リストのキー空間の両方を決める。継承値を拾うと攻撃者が
  // 選んだ束縛値・名前空間で検査したことになり、`aud` 照合もリプレイ検知も無意味になる。
  const nonceContext = ownProperty<NonceContext>(opts, 'nonceContext');
  if (nonceContext === undefined) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // ここでコンテキストを own 限定のデータスナップショットへ畳み、以降は（照合・窓選択・
  // キー組み立て・下層 `checkAndUse` への受け渡しまで）**このスナップショットだけ**を使う
  // （KB-JWT 経路 `guard.ts` と同じ形。理由は `context-snapshot.ts` の JSDoc）。
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

  // aud は本ラッパが 4012 として扱うため verifyPresentation には渡さない（3012 に潰さない）。
  // 呼び出し側は `expectedNonce` / `allowUnbound` を指定できず（型で `Omit`）、`opts.nonce` が
  // 唯一の nonce 入力になる。それを `expectedNonce` として必ず渡すため、`allowUnbound: true`
  // （＝「指定された場合は照合する」）でも nonce の照合は失われず、不一致は SD-JWT 経路と
  // 同じく 3012 になる。
  const verified = verifyPresentationClaims(jwt, {
    ...opts,
    expectedAudience: undefined,
    expectedNonce: nonce,
    allowUnbound: true,
  });

  // payload は `JSON.parse` 由来の生オブジェクト。`aud` を鎖読みすると、**`aud` を持たない
  // JWT-VP** が `Object.prototype.aud` の汚染値を「実測 aud」として採用され、バインディング
  // 検査が一致に化ける。
  const aud = ownProperty<unknown>(verified.payload, 'aud');
  if (typeof aud !== 'string') {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // 束縛値も `flow` もスナップショットから読む（値はデータプロパティに畳まれているので、
  // 何度読んでも同じ値が返る）。束縛値は 1 度だけ読んで `assertBindingMatches` で 2 度照合する
  // （`assertBinding` を 2 回呼ぶ形にはしない）。`flow` は上で 1 度読んだ結果をそのまま渡し、
  // **束縛メンバの選択と replay-window の既定窓選択の双方に同じ値を使う**（`bindingValueOf` は
  // 内部で `flow` を読み直すため使わない。単一読み（read-once）規則）。
  const expectedAudience = bindingValueForFlow(ctx, flow);
  // 空の束縛値は Verifier を識別できず「この提示宛か」を判定できない。委譲先の内包 VC 検証が同じ
  // 理由で `credentialResults[].errors` の 3012 にするより前に、本ラッパ自身の失敗面
  // である 4012 で閉じて KB-JWT 経路と失敗面を対称にする。
  // 空文字判定は SDK 内の単一の共有ヘルパで行う（層ごとに複製しない）。
  if (!isNonEmptyString(expectedAudience)) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  // 呼び出し側の `expectedAudience` も束縛値と一致必須。一致する限り実測 `aud` の照合が
  // 同じ値を検査するため、`expectedAudience` 検査は失われずに 4012 経路へ吸収される。
  // 未指定時に継承値を拾うと、正当な提示が汚染値との照合で 4012 に落とされる。
  assertBindingMatches(expectedAudience, ownProperty<string>(opts, 'expectedAudience'));
  assertBindingMatches(expectedAudience, aud);

  // 任意プロパティは自身のプロパティに限って読む。ここで継承値を**新しい
  // オブジェクトリテラルへ詰め直す**と own プロパティに化け、`assertWithinReplayWindow` 側の
  // own 限定読み取りが無効化される（`own-property.ts` の JSDoc が警告する失敗様式）。
  // 継承した `replayWindowSeconds`（例 `Infinity`）はリプレイ窓を丸ごと無効化し、
  // 継承した `nowSeconds` は攻撃者が選んだ「現在時刻」で `iat` を評価させる。
  const guardWindowSeconds = ownProperty<number>(opts, 'replayWindowSeconds');
  const guardNowSeconds = ownProperty<number>(opts, 'nowSeconds');
  const windowOpts =
    guardWindowSeconds === undefined
      ? { nowSeconds: guardNowSeconds }
      : { nowSeconds: guardNowSeconds, windowSeconds: guardWindowSeconds };
  // `iat` も own 限定で読む。鎖読みだと `iat` を持たない VP が汚染値で「窓内」に化ける。
  assertWithinReplayWindow(ownProperty<unknown>(verified.payload, 'iat'), flow, windowOpts);

  // 検証済みの `checkAndUse` をそのまま呼ぶ（`this` はストア本体に束ねる）。再度
  // `nonceStore.checkAndUse` と書くと検証した値と呼ぶ値がずれ得る。`nonceTtlMs` も同じ理由で
  // 1 度だけ読んで変数に置く（存在判定と値取得で 2 度読むと両者がずれ得る）。
  const nonceTtlMs = ownProperty<number>(opts, 'nonceTtlMs');
  await checkAndUse.call(nonceStore, nonce, ctx, {
    binding: aud,
    ...(nonceTtlMs === undefined ? {} : { ttlMs: nonceTtlMs }),
  });

  return { ...verified, audience: aud, nonce };
}

/**
 * 内包 VC を、本ラッパが解決した**実効バインド値**で検証して `credentialResults` を組み立てる
 *
 * 本ラッパは内側の VP 検証へ `expectedAudience` を渡さない（`aud` の不一致を 3012 ではなく 4012
 * として扱うのは本ラッパの責務のため）。素の `verifyPresentation` に組み立てさせると
 * `credentialResults` が audience 未指定で評価され、**内包 SD-JWT VC に付いた KB-JWT の `aud` が
 * 照合されない**（他所の Verifier 宛に束縛された KB-JWT が `valid: true` で通る）。そこで VP
 * レベルの検証には `verifyPresentationClaims` を使い、内包 VC の評価は束縛照合を終えた実測 `aud`
 * で**ここ 1 回だけ**行う。
 *
 * `opts` はスプレッドしない。継承値が own プロパティへ化け、委譲先の own 限定読み取り
 * （`own-property.ts` の JSDoc が警告する失敗様式）を無効化するため、必要な項目だけを
 * `resolvePresentationVerificationFields` と同じ読み方で拾い直す。VP は `guarded.asserted`
 * （検査済みメンバごと）をそのまま渡し、`holder` / `verifiableCredential` を読み直させない。
 *
 * @param guarded ガード検査を終えた VP レベルの検証結果と実効バインド値。
 * @param opts 本ラッパに渡された生のオプション（読み方は本関数が決める）。
 * @returns 内包 VC の検証結果を足した `VerifiedPresentation`。
 */
function withEffectiveBinding(
  guarded: GuardedPresentationClaims,
  opts: object,
): VerifiedPresentation {
  return {
    header: guarded.header,
    payload: guarded.payload,
    presentation: guarded.asserted.vp,
    ...resolvePresentationVerificationFields(
      guarded.asserted,
      {
        // 関数値の DI はプロトタイプメソッド実装を受理する（`Object.prototype` 由来だけ弾く）。
        credentialKey: nonObjectPrototypeProperty<unknown>(opts, 'credentialKey'),
        issuerTrust: ownProperty<unknown>(opts, 'issuerTrust'),
        clockSkewSeconds: ownProperty<number>(opts, 'clockSkewSeconds'),
        requireHolderBinding: ownProperty<boolean>(opts, 'requireHolderBinding'),
        // Trusted Issuer List。中継しないと、本公開ラッパを直接呼ぶ
        // 呼び出しだけが黙って「未指定」扱いになり、`isTrustedIssuer` が常に `null` で返る
        // （`requireHolderBinding` の中継漏れと同じ失敗の形）。
        trustedIssuerList: ownProperty<unknown>(opts, 'trustedIssuerList'),
        workBudget: ownProperty<unknown>(opts, 'workBudget'),
        expectedAudience: guarded.audience,
        expectedNonce: guarded.nonce,
      },
      guarded.nowSeconds,
    ),
  };
}
