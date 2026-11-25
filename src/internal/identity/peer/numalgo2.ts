/**
 * did:peer numalgo 2 のエンコード・デコード（V / E / S エレメント）。
 *
 * DIF の peer-did-method-spec に従う。
 *
 * - `.V` = 署名鍵 → verificationMethod + authentication + assertionMethod。
 * - `.E` = 暗号鍵 → keyAgreement。
 * - `.S` = サービス（base64url（no padding）の省略形 JSON）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・鍵バイト・サービス内容などの入力データを含めない。
 * - `@scure/base` / JSON パース由来の例外は cause を渡さず `VericertsError`（code `2001`）へ正規化する。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DIDDocument, Service, VerificationMethod } from '../did.js';
import { assertNumalgo2Key } from './numalgo2-keys.js';

/** DIDComm v2 サービスの type 名（省略形 `dm` の展開先）。 */
const DIDCOMM_SERVICE_TYPE = 'DIDCommMessaging';

/**
 * numalgo 2 の `.S`（service）省略形 JSON のキー対応表（peer-did-method-spec）。
 *
 * 生成時は左→右に短縮、解決時は右→左に展開する。`type` の値 `DIDCommMessaging` は `dm` に短縮する。
 */
const SERVICE_KEY_ABBREVIATIONS: ReadonlyArray<readonly [full: string, abbr: string]> = [
  ['type', 't'],
  ['serviceEndpoint', 's'],
  ['routingKeys', 'r'],
  ['accept', 'a'],
];

/** numalgo 2 の purpose code（V = 署名鍵 / E = 暗号鍵 / S = サービス）。 */
type Numalgo2Purpose = 'V' | 'E' | 'S';

/**
 * numalgo 2 の DID 本体（numalgo 直後）の要素文字列を組み立てる。
 *
 * @param verificationKeys 署名鍵（multibase base58btc）。少なくとも 1 つ必要。
 * @param keyAgreementKeys 暗号鍵（multibase base58btc）。
 * @param services サービス。
 * @returns `.V....E....S...` 形式の連結文字列。
 * @throws 鍵の multibase・multicodec・鍵長不正（V は Ed25519 / secp256k1 / P-256、E は P-256 / X25519
 *         のみ）・署名鍵未指定の場合（VericertsError、code `2001`）。
 */
export function encodeNumalgo2Elements(
  verificationKeys: readonly string[],
  keyAgreementKeys: readonly string[],
  services: readonly Service[],
): string {
  if (verificationKeys.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const parts: string[] = [];
  for (const key of verificationKeys) {
    assertNumalgo2Key(key, 'V');
    parts.push(`.V${key}`);
  }
  for (const key of keyAgreementKeys) {
    assertNumalgo2Key(key, 'E');
    parts.push(`.E${key}`);
  }
  for (const service of services) {
    parts.push(`.S${encodeService(service)}`);
  }
  return parts.join('');
}

/**
 * サービスオブジェクトを `.S` 省略形（base64url, no padding）へエンコードする。
 *
 * @param service サービスオブジェクト。
 * @returns base64url（no padding）文字列。
 */
function encodeService(service: Service): string {
  const json = JSON.stringify(abbreviateService(service));
  return base64urlnopad.encode(new TextEncoder().encode(json));
}

/**
 * サービスのキー・type 値を省略形へ置換する（`id` は省略形に含めない）。
 *
 * @param service サービスオブジェクト。
 * @returns 省略形 plain object。
 */
function abbreviateService(service: Service): Record<string, unknown> {
  const source: Record<string, unknown> = { ...service };
  // id は省略形に含めない（peer-did-method-spec では解決時に #service 系を再付与する）。
  delete source.id;
  return mapKeys(source, (key) => abbreviationOf(key), DIDCOMM_SERVICE_TYPE, 'dm');
}

/**
 * numalgo 2 の DID 本体（numalgo 直後）を解決して DID Document を構築する。
 *
 * @param did 完全な DID 文字列。
 * @param elements numalgo 直後の文字列（先頭が `.`）。
 * @returns DID Document。
 * @throws purpose code 不正・鍵 multibase / multicodec / 鍵長不正・サービス JSON 不正・署名鍵不在の場合
 *         （VericertsError、code `2001`）。
 */
export function resolveNumalgo2(did: string, elements: string): DIDDocument {
  if (!elements.startsWith('.')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const rawElements = elements.slice(1).split('.');

  const verificationMethod: VerificationMethod[] = [];
  const authentication: string[] = [];
  const assertionMethod: string[] = [];
  const keyAgreement: string[] = [];
  const services: Service[] = [];
  let keyIndex = 0;
  let serviceIndex = 0;

  for (const element of rawElements) {
    const purpose = parsePurpose(element[0]);
    const value = element.slice(1);
    if (value.length === 0) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (purpose === 'S') {
      services.push(decodeService(did, value, serviceIndex));
      serviceIndex += 1;
      continue;
    }
    keyIndex += 1;
    const id = `${did}#key-${keyIndex}`;
    assertNumalgo2Key(value, purpose); // multibase・multicodec・鍵長の検証（鍵バイトはメッセージに含めない）。
    verificationMethod.push({ id, type: 'Multikey', controller: did, publicKeyMultibase: value });
    if (purpose === 'V') {
      authentication.push(id);
      assertionMethod.push(id);
    } else {
      keyAgreement.push(id);
    }
  }

  // 署名鍵（V）が 1 つも無い（E / S のみ）DID は拒否する。E は verificationMethod に載るため件数ではなく authentication で判定する。
  if (authentication.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return buildDocument(did, {
    verificationMethod,
    authentication,
    assertionMethod,
    keyAgreement,
    services,
  });
}

/** 解決結果の DID Document を組み立てる（空の keyAgreement / service は省略する）。 */
function buildDocument(
  did: string,
  parts: {
    verificationMethod: VerificationMethod[];
    authentication: string[];
    assertionMethod: string[];
    keyAgreement: string[];
    services: Service[];
  },
): DIDDocument {
  const doc: {
    '@context': string[];
    id: string;
    verificationMethod: VerificationMethod[];
    authentication: string[];
    assertionMethod: string[];
    keyAgreement?: string[];
    service?: Service[];
  } = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: parts.verificationMethod,
    authentication: parts.authentication,
    assertionMethod: parts.assertionMethod,
  };
  if (parts.keyAgreement.length > 0) {
    doc.keyAgreement = parts.keyAgreement;
  }
  if (parts.services.length > 0) {
    doc.service = parts.services;
  }
  return doc;
}

/**
 * エレメント先頭文字を purpose code に解釈する。
 *
 * @param code エレメント先頭文字。
 * @returns purpose code。
 * @throws 未対応 purpose の場合（VericertsError、code `2001`）。
 */
function parsePurpose(code: string | undefined): Numalgo2Purpose {
  if (code === 'V' || code === 'E' || code === 'S') {
    return code;
  }
  throw new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * `.S` 省略形サービスを Service オブジェクトへ復元する。
 *
 * @param did 完全な DID 文字列。
 * @param encoded base64url（no padding）省略形サービス JSON。
 * @param serviceIndex 0 始まりのサービス連番（id 自動付与用）。
 * @returns Service オブジェクト。
 * @throws base64url / JSON 不正・type / serviceEndpoint 欠落の場合（VericertsError、code `2001`）。
 */
function decodeService(did: string, encoded: string, serviceIndex: number): Service {
  let json: unknown;
  try {
    json = parseJsonWithoutPrototype(new TextDecoder().decode(base64urlnopad.decode(encoded)));
  } catch {
    // base64url / JSON パース由来の例外は入力を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const expanded = expandService(json as Record<string, unknown>);
  const { type, serviceEndpoint } = expanded;
  if (typeof type !== 'string' || serviceEndpoint === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // id が無ければ peer-did-method-spec の慣例（#service, #service-1, ...）で付与する。
  const id =
    typeof expanded.id === 'string'
      ? expanded.id
      : `${did}#service${serviceIndex === 0 ? '' : `-${serviceIndex}`}`;
  return { ...expanded, id, type, serviceEndpoint } as unknown as Service;
}

/** 省略形サービスのキー・type 値を完全形へ展開する。 */
function expandService(abbreviated: Record<string, unknown>): Record<string, unknown> {
  return mapKeys(abbreviated, (key) => fullNameOf(key), 'dm', DIDCOMM_SERVICE_TYPE);
}

/**
 * オブジェクトのキーを `rename` で変換しつつ、`type` の値を `typeFrom`→`typeTo` に置換する。
 *
 * `rename` が `undefined` を返したキーはそのまま残す（省略表に無いメンバの保持）。
 *
 * @param source 変換元 plain object。
 * @param rename キー名変換（対応無しは `undefined`）。
 * @param typeFrom type 値の置換元。
 * @param typeTo type 値の置換先。
 * @returns 変換後の、`Object.prototype` を継承しないオブジェクト。
 */
function mapKeys(
  source: Record<string, unknown>,
  rename: (key: string) => string | undefined,
  typeFrom: string,
  typeTo: string,
): Record<string, unknown> {
  // 通常のオブジェクトリテラルだと Object.prototype を継承し、呼び出し元（decodeService）の
  // 分割代入がキーを持たない結果でも継承値を拾ってしまう。
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(source)) {
    const mapped = rename(key);
    if (mapped === undefined) {
      result[key] = value;
      continue;
    }
    // type に相当するキー（'type' or 't'）の値だけ置換する。
    const isTypeKey = mapped === 'type' || key === 'type';
    result[mapped] = isTypeKey && value === typeFrom ? typeTo : value;
  }
  return result;
}

/** 完全名 → 省略名（対応無しは `undefined`）。 */
function abbreviationOf(fullName: string): string | undefined {
  return SERVICE_KEY_ABBREVIATIONS.find(([full]) => full === fullName)?.[1];
}

/** 省略名 → 完全名（対応無しは `undefined`）。 */
function fullNameOf(abbr: string): string | undefined {
  return SERVICE_KEY_ABBREVIATIONS.find(([, a]) => a === abbr)?.[0];
}
