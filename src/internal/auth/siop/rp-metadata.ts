/**
 * SIOPv2 の RP メタデータ（`client_metadata` / `registration` / `client_metadata_uri` の取得文書）の展開。
 *
 * `parse.ts` が要求のクエリ / JSON から読んだ値、`client-metadata-uri.ts` が取得した文書を、同じ `RPRegistration` へ
 * 展開する。例外メッセージ・`context` に RP メタデータの内容を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { RPRegistration } from './types.js';

/** 値が文字列のみからなる配列か（RP メタデータの配列フィールド検証用）。 */
function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

/**
 * RP メタデータ（`registration` / `client_metadata`）の JSON を展開する。文字列は JSON として解析し、
 * オブジェクトはそのまま使う。
 *
 * `decodeURIComponent` するのは旧 `registration`（url-encoded JSON を URLSearchParams が 1 度デコードした
 * あとにさらにデコードする既存の挙動）だけである。`client_metadata` は標準どおり 1 度のデコードで JSON になる。
 *
 * @throws JSON 構文不正・想定外の形の場合（VericertsError、code `4001`）。
 */
function decodeMetadata(raw: unknown, name: 'registration' | 'client_metadata'): unknown {
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(name === 'registration' ? decodeURIComponent(raw) : raw);
  } catch {
    throw new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: `${name}_json` },
    });
  }
}

/**
 * RP メタデータ 1 件（`registration` / `client_metadata`）を `RPRegistration` へ展開する。
 *
 * JSON.parse の戻り値は攻撃者が形を選べる任意オブジェクトなので、各フィールドは own プロパティに
 * 限って読む（プロトタイプ汚染下で「省略したメタデータ」が汚染値を採用してしまうのを防ぐ）。
 *
 * @throws 想定外の形の場合（VericertsError、code `4001`）。
 */
export function parseMetadata(
  raw: unknown,
  name: 'registration' | 'client_metadata',
  strict: boolean,
): RPRegistration {
  const decoded = decodeMetadata(raw, name);
  const shapeError = () =>
    new VericertsError(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED, {
      context: { reason: `${name}_shape` },
    });
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    throw shapeError();
  }
  const subjectSyntaxTypesSupported = ownProperty<unknown>(
    decoded,
    'subject_syntax_types_supported',
  );
  const idTokenSigningAlgValuesSupported = ownProperty<unknown>(
    decoded,
    'id_token_signing_alg_values_supported',
  );
  const idTokenSignedResponseAlg = ownProperty<unknown>(decoded, 'id_token_signed_response_alg');
  // 署名アルゴリズムは、複数形の `id_token_signing_alg_values_supported`（配列）か標準の
  // `id_token_signed_response_alg`（単一の文字列）の少なくとも一方で宣言されていること。
  if (
    !isStringArray(subjectSyntaxTypesSupported) ||
    (idTokenSigningAlgValuesSupported !== undefined &&
      !isStringArray(idTokenSigningAlgValuesSupported)) ||
    (idTokenSignedResponseAlg !== undefined && !isNonBlankString(idTokenSignedResponseAlg)) ||
    (idTokenSigningAlgValuesSupported === undefined && idTokenSignedResponseAlg === undefined)
  ) {
    throw shapeError();
  }
  const jwtVpAlgValuesSupported = parseJwtVpAlgValues(decoded, strict ? shapeError : undefined);
  return {
    subjectSyntaxTypesSupported,
    ...(idTokenSigningAlgValuesSupported !== undefined ? { idTokenSigningAlgValuesSupported } : {}),
    ...(idTokenSignedResponseAlg !== undefined ? { idTokenSignedResponseAlg } : {}),
    ...(jwtVpAlgValuesSupported !== undefined ? { jwtVpAlgValuesSupported } : {}),
  };
}

/**
 * `vp_formats_supported.jwt_vp.alg_values`（OID4VP §5.1）を取り出す。宣言が無ければ `undefined`。
 * 宣言があるのに形が違う（`alg_values` が文字列の配列でない等）ものは検証できないので、`shapeError` があれば
 * （`vp_token` を返す要求）拒否し、無ければ（VP Token を返さない旧来の要求。この宣言を使わない）無かったことにする。
 */
function parseJwtVpAlgValues(
  metadata: object,
  shapeError: (() => VericertsError) | undefined,
): string[] | undefined {
  const reject = (): undefined => {
    if (shapeError !== undefined) throw shapeError();
    return undefined;
  };
  const formats = ownProperty<unknown>(metadata, 'vp_formats_supported');
  if (formats === undefined) return undefined;
  if (formats === null || typeof formats !== 'object' || Array.isArray(formats)) return reject();
  const jwtVp = ownProperty<unknown>(formats, 'jwt_vp');
  if (jwtVp === undefined) return undefined;
  if (jwtVp === null || typeof jwtVp !== 'object' || Array.isArray(jwtVp)) return reject();
  const algValues = ownProperty<unknown>(jwtVp, 'alg_values');
  if (algValues === undefined) return undefined;
  return isStringArray(algValues) ? algValues : reject();
}

/**
 * `client_metadata_uri` から取得した RP メタデータ文書を `RPRegistration` へ展開する。
 * `vp_token` を返す要求と同じく、検証できない形は fail-closed で拒否する。
 *
 * @throws 想定外の形の場合（VericertsError、code `4001`）。
 */
export function parseFetchedClientMetadata(document: unknown): RPRegistration {
  return parseMetadata(document, 'client_metadata', true);
}
