/**
 * JWE Compact Serialization の暗号化プリミティブ（ECDH-ES 鍵合意 + AES-GCM）。
 *
 * 準拠規格: RFC 7516（JWE）/ RFC 7518 §4.6（ECDH-ES）/ §5.3（A256GCM）/
 * RFC 3394（AES Key Wrap）。
 *
 * 対応する鍵管理アルゴリズム:
 *
 * | `alg`            | 鍵合意                                   | CEK                              |
 * | ---------------- | ---------------------------------------- | -------------------------------- |
 * | `ECDH-ES`        | Direct Key Agreement（RFC 7518 §4.6.1）  | Concat KDF の出力をそのまま使う  |
 * | `ECDH-ES+A256KW` | Key Agreement with Key Wrapping（§4.6.1）| ランダム CEK を A256KW でラップ  |
 *
 * `enc` は `A256GCM` のみ対応する。曲線は P-256（`crv=P-256`）のみ対応する（HAIP / EUDI ARF の
 * SD-JWT VC プロファイルが要求する ES256 / P-256 に揃える）。
 *
 * レイヤリング: ECDH-ES 鍵合意と Concat KDF は `ecdh.ts`、AES-GCM / AES-KW は Web Crypto
 * （`globalThis.crypto.subtle`）に委譲する。`jose` 等の外部 JOSE ライブラリには依存しない。
 *
 * 失敗はすべて `VericertsError` へ正規化する。受信者鍵が使えない場合は `8036`、鍵導出・暗号化演算の失敗は `8037`。
 *
 * セキュリティ上の注意:
 * - 平文（VP Token）・共有秘密・CEK・エフェメラル秘密鍵を例外メッセージ・`context`・`cause` に
 *   一切含めない。Web Crypto / @noble 由来の例外は `cause` を渡さず握りつぶす。
 * - エフェメラル鍵ペアは暗号化 1 回ごとに新規生成する（`ecdh.ts` の責務）。
 * - CEK / IV は暗号化のたびにランダム生成する（GCM の IV 再利用は機密性・完全性を破壊する）。
 */

import { base64urlnopad } from '@scure/base';
import { toBufferSource } from '../../asset/bytes.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { agreeEphemeralKey, KEY_LENGTH } from './ecdh.js';

/** ECDH-ES 直接鍵合意（RFC 7518 §4.6.1）。Concat KDF の出力を CEK にする。 */
export const JWE_ALG_ECDH_ES = 'ECDH-ES' as const;
/** ECDH-ES + AES-256 Key Wrap（RFC 7518 §4.6.1 / RFC 3394）。ランダム CEK をラップする。 */
export const JWE_ALG_ECDH_ES_A256KW = 'ECDH-ES+A256KW' as const;
/** AES-256-GCM コンテンツ暗号化（RFC 7518 §5.3）。 */
export const JWE_ENC_A256GCM = 'A256GCM' as const;

/** 本 SDK が対応する JWE `alg`（鍵管理アルゴリズム）。 */
export type JweAlg = typeof JWE_ALG_ECDH_ES | typeof JWE_ALG_ECDH_ES_A256KW;
/** 本 SDK が対応する JWE `enc`（コンテンツ暗号化アルゴリズム）。 */
export type JweEnc = typeof JWE_ENC_A256GCM;

/** 対応 `alg` の集合（`client_metadata` の値検証に使う）。 */
export const SUPPORTED_JWE_ALGS: ReadonlySet<string> = new Set<JweAlg>([
  JWE_ALG_ECDH_ES,
  JWE_ALG_ECDH_ES_A256KW,
]);
/** 対応 `enc` の集合（`client_metadata` の値検証に使う）。 */
export const SUPPORTED_JWE_ENCS: ReadonlySet<string> = new Set<JweEnc>([JWE_ENC_A256GCM]);

/** GCM の IV 長（バイト）。RFC 7518 §5.3 が 96bit を要求する。 */
const IV_LENGTH = 12;
/** GCM 認証タグ長（バイト = 128bit）。 */
const TAG_LENGTH = 16;
/** GCM 認証タグ長（ビット）。Web Crypto の `tagLength` に渡す。 */
const TAG_LENGTH_BITS = 128;

/** JWE 暗号化のパラメータ（`alg` / `enc` / ヘッダに載せる補助情報）。 */
export interface JweEncryptParams {
  /** 鍵管理アルゴリズム。 */
  readonly alg: JweAlg;
  /** コンテンツ暗号化アルゴリズム。 */
  readonly enc: JweEnc;
  /** 受信者公開鍵の `kid`（判明している場合のみ protected header に載せる）。 */
  readonly kid?: string;
  /** PartyUInfo（`apu`）の生バイト列。未指定なら空（RFC 7518 §4.6.2 の既定）。 */
  readonly apu?: Uint8Array;
  /** PartyVInfo（`apv`）の生バイト列。未指定なら空。 */
  readonly apv?: Uint8Array;
}

/**
 * CSPRNG から指定バイト数を取得する。
 *
 * `crypto.getRandomValues` が使えない実行環境で生の `Error` が escape しないよう 8037 へ正規化する
 * （乱数が得られないまま暗号化を続けるのは危険なので、フォールバックはしない）。
 *
 * @throws 乱数生成に失敗した場合（VericertsError、code `8037`）。
 */
function randomBytes(length: number): Uint8Array {
  try {
    return crypto.getRandomValues(new Uint8Array(length));
  } catch {
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_FAILED, {
      context: { reason: 'random_generation_failed' },
    });
  }
}

/** ランダム CEK を AES-256 Key Wrap（RFC 3394）でラップする。 */
async function wrapCek(kek: Uint8Array, cek: Uint8Array): Promise<Uint8Array> {
  try {
    const kekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(kek),
      { name: 'AES-KW' },
      false,
      ['wrapKey'],
    );
    // wrapKey は CryptoKey を要求するため、CEK を一旦 extractable な AES-GCM 鍵として取り込む。
    const cekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(cek),
      { name: 'AES-GCM' },
      true,
      ['encrypt'],
    );
    return new Uint8Array(await crypto.subtle.wrapKey('raw', cekKey, kekKey, 'AES-KW'));
  } catch {
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_FAILED, {
      context: { reason: 'cek_wrap_failed' },
    });
  }
}

/** AES-256-GCM でコンテンツを暗号化し、暗号文と認証タグを分離して返す。 */
async function encryptContent(
  cek: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ readonly ciphertext: Uint8Array; readonly tag: Uint8Array }> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      toBufferSource(cek),
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    );
    const buf = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toBufferSource(iv),
          tagLength: TAG_LENGTH_BITS,
          additionalData: toBufferSource(aad),
        },
        key,
        toBufferSource(plaintext),
      ),
    );
    // Web Crypto は「暗号文 || 16 バイトタグ」を返す。JWE Compact は両者を別セグメントで送る。
    return {
      ciphertext: buf.slice(0, buf.length - TAG_LENGTH),
      tag: buf.slice(buf.length - TAG_LENGTH),
    };
  } catch {
    throw new VericertsError(ErrorCodes.VP_RESPONSE_ENCRYPTION_FAILED, {
      context: { reason: 'content_encryption_failed' },
    });
  }
}

/**
 * 平文を JWE Compact Serialization（RFC 7516 §7.1）へ暗号化する。
 *
 * 生成される 5 セグメントは
 * `BASE64URL(protected) . BASE64URL(encrypted_key) . BASE64URL(iv) . BASE64URL(ciphertext) . BASE64URL(tag)`。
 * `alg=ECDH-ES`（direct）では `encrypted_key` は空文字列になる（RFC 7518 §4.6.1）。
 * AAD は RFC 7516 §5.1 のとおり `ASCII(BASE64URL(protected))` とする。
 *
 * 失敗は必ず `VericertsError` で返す（生の `Error` を escape させない）。
 *
 * @param plaintext 暗号化する平文（UTF-8 文字列。本用途では VP 応答 JSON）。
 * @param recipientJwk 受信者（Verifier）の EC 公開鍵 JWK（`crv=P-256`）。
 * @param params `alg` / `enc` および `kid` / `apu` / `apv`。
 * @returns JWE Compact Serialization 文字列。
 * @throws 受信者鍵が未対応 / 点が曲線上にない場合（VericertsError、code `8036`）、
 *         鍵導出・暗号化演算に失敗した場合（VericertsError、code `8037`）。
 */
export async function encryptJweCompact(
  plaintext: string,
  recipientJwk: PublicKeyJwk,
  params: JweEncryptParams,
): Promise<string> {
  // 任意プロパティは自身のプロパティに限って読む。`params.apu ?? 既定値` は
  // プロトタイプ鎖を辿るため、`apu` を省略した正当な呼び出し（`wallet_nonce` 無し）でも
  // `Object.prototype.apu` の汚染値が Concat KDF の PartyUInfo に入り、そのまま JWE
  // protected header にも出力される。`kid` も同様に攻撃者が選んだ鍵 ID がヘッダへ載る。
  const apu = ownProperty<Uint8Array>(params, 'apu') ?? new Uint8Array(0);
  const apv = ownProperty<Uint8Array>(params, 'apv') ?? new Uint8Array(0);
  const kid = ownProperty<string>(params, 'kid');

  const isDirect = params.alg === JWE_ALG_ECDH_ES;
  // RFC 7518 §4.6.2: AlgorithmID は direct なら `enc`、Key Wrapping なら `alg`。
  const { epk, derived } = agreeEphemeralKey(
    recipientJwk,
    isDirect ? params.enc : params.alg,
    apu,
    apv,
  );
  const cek = isDirect ? derived : randomBytes(KEY_LENGTH);
  const encryptedKey = isDirect ? new Uint8Array(0) : await wrapCek(derived, cek);

  const header: Record<string, unknown> = {
    alg: params.alg,
    enc: params.enc,
    epk,
    ...(kid !== undefined ? { kid } : {}),
    ...(apu.length > 0 ? { apu: base64urlnopad.encode(apu) } : {}),
    ...(apv.length > 0 ? { apv: base64urlnopad.encode(apv) } : {}),
  };
  const protectedHeader = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(header)));

  const iv = randomBytes(IV_LENGTH);
  const { ciphertext, tag } = await encryptContent(
    cek,
    iv,
    new TextEncoder().encode(plaintext),
    // RFC 7516 §5.1 手順 14: AAD は protected header の ASCII 表現。
    new TextEncoder().encode(protectedHeader),
  );

  return [
    protectedHeader,
    base64urlnopad.encode(encryptedKey),
    base64urlnopad.encode(iv),
    base64urlnopad.encode(ciphertext),
    base64urlnopad.encode(tag),
  ].join('.');
}
