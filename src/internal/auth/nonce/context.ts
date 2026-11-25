/**
 * `NonceContext` の正規化ユーティリティ。
 *
 * コンテキストは「flow + 束縛対象（clientId / issuer / audience）」で構成され、
 * 拒否リストのキー空間を分離する。`state` はキーに含めないため、同じ `client_id` と `nonce` の組は
 * 別の `state` で提示してもリプレイとして検出される。
 *
 * ## `*Of`（ctx 版）と `*From`（解決済み値版）の使い分け
 *
 * 照合とキー組み立ての**双方**を行う場合、および**複数回キーを組み立てる**場合は `*Of`（`contextKeyOf` /
 * `entryKeyOf`）を繰り返し呼んではならない。呼ぶたびに `resolveBinding` が走り、`flow` / 束縛メンバを
 * own の**アクセサ**として持つ `NonceContext` では読み取りごとに別値が返り得る（TOCTOU）。
 * `resolveBinding` で 1 度だけ解決し、以降は `*From` へ同じ `{ flow, value }` を渡すこと。
 *
 * この規律は SDK 利用者にも必要なため、`resolveBinding` / `contextKeyFrom` / `entryKeyFrom` は
 * `assertBindingMatches` と同じく**公開バレル（`exports/auth.ts`）に載せる**。`*Of` だけが
 * 公開されている状態では、照合を通した読み取り結果からキーを組み立てる経路が公開面に無く、利用者は
 * TOCTOU を踏む `*Of` の呼び直ししか選べなかった（`assertBindingMatches` を公開したのと同型の欠落）。
 *
 * なお、この規律の適用先であるキー組み立て関数（`contextKeyFrom` / `entryKeyPrefixFrom` /
 * `entryKeyFrom` / `contextKeyOf` / `entryKeyOf`）は `context-keys.ts` にある。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { timingSafeEqualString } from '../../timing-safe.js';
import type { NonceContext, NonceFlow } from './types.js';

/**
 * flow ごとの既定 TTL（ms）。
 *
 * `one-time-credential` の保持期間は VC の `exp` まで。呼び出し側が TTL を指定する（未指定は `RangeError`）。
 * VC の有効期間中に `jti` の記録が消えると、同じ VC の再利用を検出できなくなる。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export const DEFAULT_TTL_MS_BY_FLOW: Readonly<
  Record<Exclude<NonceFlow, 'one-time-credential'>, number>
> = {
  oid4vp: 300_000,
  oid4vci: 300_000,
  siopv2: 300_000,
  'wua-pop': 600_000,
  // DPoP proof は短命（±30 秒）。受理ウィンドウ全域をカバーする 60 秒を保持する。
  dpop: 60_000,
};

/** flow ごとの束縛メンバ名。 */
const BINDING_MEMBER_BY_FLOW: Readonly<Record<NonceFlow, string>> = {
  oid4vp: 'clientId',
  oid4vci: 'issuer',
  siopv2: 'clientId',
  'wua-pop': 'audience',
  'one-time-credential': 'issuer',
  dpop: 'jkt',
};

/**
 * 既知の flow であることを検証し、その束縛メンバ名を返す（`flow` の読み取りは行わない）。
 *
 * 「既知 flow の判定」と「束縛メンバの選択」の実体は本関数だけに置く。層ごとに複製すると
 * 規則が二重管理になり、`BINDING_MEMBER_BY_FLOW` の更新が片方にしか反映されない事故が起きる。
 *
 * @param flow すでに own 限定で読んだ `flow`（未検証の生値でよい）。
 * @returns その flow が束縛値として読むメンバ名。
 * @throws `NONCE_BINDING_MISMATCH`（4012）既知の flow でない場合。
 */
function bindingMemberFor(flow: unknown): string {
  // 対応表自身もオブジェクトリテラルで `Object.prototype` を継承するため、own 限定で引く
  // （ガードが新しい鎖読みを持ち込まない）。既知 flow の集合は本表のキーそのものになる。
  const member =
    typeof flow === 'string' ? ownProperty<string>(BINDING_MEMBER_BY_FLOW, flow) : undefined;
  if (member === undefined) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  return member;
}

/**
 * コンテキストの `flow` を own 限定で 1 回だけ読み、既知の flow とその束縛メンバ名を返す。
 *
 * 鎖読みだと `flow` を own に持たない context でも `Object.prototype.flow` の汚染値がキー空間・TTL の
 * 選択に使われる。未知・欠落は fail-closed で拒否する。また **本関数を 2 回呼ぶ（＝ `flow` を
 * 2 度読む）**と読み取りごとに別値が返り得て、キー接頭辞の flow と束縛メンバの選択根拠がずれる
 * （冒頭の TOCTOU）。flow は 1 回だけ読み、以降は本関数の戻り値を使い回す。
 *
 * @param ctx 発行コンテキスト。
 * @returns 検証済み flow と、その flow が束縛値として読むメンバ名。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` が own に無い / 既知の flow でない場合。
 */
function resolveFlow(ctx: NonceContext): { flow: NonceFlow; member: string } {
  const flow = ownProperty<unknown>(ctx, 'flow');
  return { flow: flow as NonceFlow, member: bindingMemberFor(flow) };
}

/**
 * flow の既定 TTL を返す。既定値を持たない flow では `undefined`。
 *
 * @param flow 対象 flow。
 * @returns 既定 TTL（ms）。`one-time-credential` は `undefined`。
 */
export function defaultTtlMsFor(flow: NonceFlow): number | undefined {
  // 表は own 限定で引く。呼び出し側が TTL を指定する one-time-credential に既定値はない。
  return ownProperty<number>(DEFAULT_TTL_MS_BY_FLOW, flow);
}

/**
 * 束縛メンバを own 限定で読み、文字列であることを検証して返す。
 *
 * @param ctx 発行コンテキスト。
 * @param member `resolveFlow` が決めた束縛メンバ名。
 * @returns 束縛対象の識別子。
 * @throws `NONCE_BINDING_MISMATCH`（4012）当該メンバが own に無い / 文字列でない場合。
 */
function bindingValueFor(ctx: NonceContext, member: string): string {
  // `NonceContext` のメンバはプロトタイプ鎖を辿らず own 限定で読む。鎖読みだと、当該メンバを
  // own に持たない context ＋ `Object.prototype` 汚染下で **`aud` 照合の対象も拒否リストのキー空間も
  // 攻撃者が選んだ値**になる。`NonceContext` は純データ（文字列メンバのみ）なので `ownProperty` を使う。
  const value = ownProperty<unknown>(ctx, member);
  // 束縛値が own に無ければ汚染値で代替せず fail-closed に倒す（`as` で下流へ流さない）。
  if (typeof value !== 'string') {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
  return value;
}

/**
 * `flow` と束縛値を **1 パスで**解決する（`flow` 1 回・束縛メンバ 1 回だけ読む）。
 *
 * 照合とキー組み立ての両方を必要とする呼び出し元（`store.ts`）はこの戻り値だけを使う。照合の後に
 * コンテキストを読み直すと、束縛メンバを own のアクセサとして持つ `NonceContext` では読み取りごとに
 * 別値が返り得るため、**照合を通した値とは別のキー空間**へ消費記録が書かれ、nonce がリプレイ可能な
 * まま残る。`*Of` との使い分けと、公開バレルへ載せる判断基準は冒頭の節に記す。
 *
 * @param ctx 発行コンテキスト。
 * @returns 検証済み flow と、その flow の束縛対象の識別子。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` / 束縛メンバを own 読みできない場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function resolveBinding(ctx: NonceContext): { flow: NonceFlow; value: string } {
  const { flow, member } = resolveFlow(ctx);
  return { flow, value: bindingValueFor(ctx, member) };
}

/**
 * コンテキストの束縛対象値（`aud` / `client_id` / `issuer` / `jkt`）を取り出す。
 *
 * @param ctx 発行コンテキスト。
 * @returns 束縛対象の識別子。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` / 束縛メンバを own 読みできない場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function bindingValueOf(ctx: NonceContext): string {
  return resolveBinding(ctx).value;
}

/**
 * **解決済みの** flow に対応する束縛対象値を取り出す（`bindingValueOf` の「flow を受け取る」版）。
 *
 * 呼び出し元（`guard.ts` / `vp-guard.ts`）は `flow` をすでに own 限定で 1 度読み、`undefined` でない
 * ことを確かめている。その読み取り結果をそのまま渡す前提の関数で、**`ctx` から `flow` を読み直さない**。
 * 読み直すと **replay-window の既定窓を選ぶ flow と束縛メンバを選ぶ flow が別 flow になる**（窓選択は
 * 1 回目、束縛メンバは 2 回目に従う）。これは **単一読み（read-once）**規則（「入口で 1 度だけ
 * 読み、照合・窓選択・キー組み立てのすべてに同じ読み取り結果を使う」）の違反である。呼び出し元は入口で
 * スナップショット化した `ctx`（`context-snapshot.ts`）を渡すため、本関数の読みが唯一の束縛値読みになる。
 *
 * @param ctx 発行コンテキスト。
 * @param flow 呼び出し元が own 限定で 1 度読んだ `flow`。
 * @returns 束縛対象の識別子。
 * @throws `NONCE_BINDING_MISMATCH`（4012）`flow` が既知でない / 束縛メンバを own 読みできない場合。
 */
export function bindingValueForFlow(ctx: NonceContext, flow: NonceFlow): string {
  return bindingValueFor(ctx, bindingMemberFor(flow));
}

/**
 * 実測のバインディング対象値とコンテキストの束縛値を定数時間で比較する。
 *
 * 同一の提示に対して照合とキー組み立ての**両方**を行う場合、および**複数回照合する**場合は本関数を使って
 * はならない（呼ぶたびに束縛値が読まれ、読み取りごとに別値が返り得る）。`bindingValueOf`（照合のみ）または
 * `resolveBinding`（照合 ＋ キー組み立て）で 1 度だけ読み、`assertBindingMatches` で照合すること。SDK 内部の
 * 呼び出し元（`guard.ts` / `vp-guard.ts` / `store.ts`）はいずれもこの形に揃っており、本関数は「1 回だけ
 * 照合し、キーを組み立てない」利用者向けの公開 API として残している。
 *
 * @param ctx 発行コンテキスト。
 * @param actual KB-JWT の `aud` や実測 `client_id` 等。`undefined` なら検査しない。
 * @throws `NONCE_BINDING_MISMATCH`（4012）不一致 / `flow` / 束縛メンバを own 読みできない場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function assertBinding(ctx: NonceContext, actual: string | undefined): void {
  if (actual === undefined) {
    return;
  }
  assertBindingMatches(bindingValueOf(ctx), actual);
}

/**
 * 取得済みの束縛値と実測値が一致するか検査する（`assertBinding` の値版）。
 *
 * 同一の提示に対して束縛値を**複数回照合する**呼び出し元（`guard.ts` は呼び出し側 `audience` と KB-JWT の
 * 実測 `aud` の 2 つを照合する）、および照合した値からそのまま拒否リストのキーを組み立てる呼び出し元
 * （`store.ts` は `resolveBinding` の戻り値で照合とキー組み立てを行う）向け。`assertBinding` を 2 回呼ぶと
 * `bindingValueOf` も 2 回走り、`flow` を own のアクセサとして持つ `NonceContext` では読み取りごとに別値が
 * 返り得る（冒頭の TOCTOU）。束縛値は 1 度だけ読み、以降は戻り値を使い回すこと。
 *
 * 本関数は `assertBinding` / `bindingValueOf` と同じく**公開バレル（`exports/auth.ts`）に載せる**
 * その 2 つが公開済みのまま本関数だけ internal だと、上記の規律（束縛値を 1 度だけ
 * 読んで本関数で照合する）を SDK 利用者が守れず、公開 API 上は TOCTOU を踏む `assertBinding` の
 * 2 回呼びしか選べなかった。
 *
 * @param expected `bindingValueOf` で 1 度だけ取得した束縛値。
 * @param actual KB-JWT の `aud` や呼び出し側 `audience` 等。`undefined` なら検査しない。
 * @throws `NONCE_BINDING_MISMATCH`（4012）不一致の場合。
 *
 * @experimental 公開直後は挙動・シグネチャが変わり得る（v1.1 で `@stable` 昇格予定）。
 */
export function assertBindingMatches(expected: string, actual: string | undefined): void {
  if (actual === undefined) {
    return;
  }
  if (!timingSafeEqualString(expected, actual)) {
    throw new VericertsError(ErrorCodes.NONCE_BINDING_MISMATCH);
  }
}
