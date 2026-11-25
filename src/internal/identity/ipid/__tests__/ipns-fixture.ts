/**
 * did:ipid テスト用の IPNS レコード生成（V2 署名つき、Kubo の `name/publish` が返す形）。
 *
 * 本番コード（`ipns-record.ts`）は検証のみを持つため、生成側はテストだけが必要とする。
 * 名前の公開鍵は `seed` を 32 バイト全てに敷いた秘密鍵から導出する（`cid-fixture.ts` の `ipnsNameOf`）。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { encodeCborHeader } from '../../../cbor.js';
import { ipnsNameOf, rawCidOf } from './cid-fixture.js';

const encoder = new TextEncoder();

/** IPNS 所有者の Ed25519 秘密鍵（`seed` を 32 バイトに敷く）。 */
export function ipnsSecretOf(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed);
}

/** IPNS レコードの組み立て設定。省略値は「正当なレコード」。 */
export interface IpnsRecordSpec {
  /** レコードの `Value`（既定 `/ipfs/<cid>`）。 */
  readonly value?: string;
  /** 有効期限（RFC 3339、既定は 1 時間後）。 */
  readonly validity?: string;
  /** `Sequence`（既定 1）。 */
  readonly sequence?: number;
  /** 署名に使う秘密鍵の seed（既定は名前と同じ seed。別鍵で署名した偽造を作るときに指定）。 */
  readonly signerSeed?: number;
  /** 署名後に protobuf 側の `Value` だけを差し替える（署名外フィールドの改ざん）。 */
  readonly outsideValue?: string;
  /** 署名後に `data` を壊す。 */
  readonly tamperData?: boolean;
}

function cborText(text: string): Uint8Array {
  const bytes = encoder.encode(text);
  return Uint8Array.from([...encodeCborHeader(3, bytes.length), ...bytes]);
}

function cborBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from([...encodeCborHeader(2, bytes.length), ...bytes]);
}

function cborUint(value: number): Uint8Array {
  return encodeCborHeader(0, value);
}

function varint(value: number): number[] {
  const out: number[] = [];
  let rest = value;
  while (rest >= 0x80) {
    out.push((rest & 0x7f) | 0x80);
    rest = Math.floor(rest / 128);
  }
  out.push(rest);
  return out;
}

function lengthDelimited(field: number, bytes: Uint8Array): number[] {
  return [(field << 3) | 2, ...varint(bytes.length), ...bytes];
}

function varintField(field: number, value: number): number[] {
  return [field << 3, ...varint(value)];
}

/** 署名済み IPNS レコード（protobuf `IpnsEntry`）を返す。 */
export function ipnsRecordOf(
  seed: number,
  cid: string,
  spec: IpnsRecordSpec = {},
): Uint8Array<ArrayBuffer> {
  const value = encoder.encode(spec.value ?? `/ipfs/${cid}`);
  const validity = encoder.encode(
    spec.validity ??
      new Date(Date.now() + 3_600_000).toISOString().replace(/\.\d+Z$/, '.000000000Z'),
  );
  const sequence = spec.sequence ?? 1;
  const data = Uint8Array.from([
    ...encodeCborHeader(5, 5),
    ...cborText('TTL'),
    ...cborUint(3_600_000_000_000),
    ...cborText('Value'),
    ...cborBytes(value),
    ...cborText('Sequence'),
    ...cborUint(sequence),
    ...cborText('Validity'),
    ...cborBytes(validity),
    ...cborText('ValidityType'),
    ...cborUint(0),
  ]);
  const signed = Uint8Array.from([...encoder.encode('ipns-signature:'), ...data]);
  const signature = ed25519.sign(signed, ipnsSecretOf(spec.signerSeed ?? seed));
  const outside = spec.outsideValue === undefined ? value : encoder.encode(spec.outsideValue);
  const sentData =
    spec.tamperData === true ? data.map((byte, i) => (i === 20 ? byte ^ 1 : byte)) : data;
  return Uint8Array.from([
    ...lengthDelimited(1, outside),
    ...varintField(3, 0),
    ...lengthDelimited(4, validity),
    ...varintField(5, sequence),
    ...varintField(6, 3_600_000_000_000),
    ...lengthDelimited(8, signature),
    ...lengthDelimited(9, sentData),
  ]);
}

/** {@link ipnsGateway} が返す Gateway ダブル。 */
export interface IpnsGateway {
  /** `globalThis.fetch` へ差し替える実装。 */
  readonly fetch: typeof fetch;
  /** 受けた URL（順序どおり）。 */
  readonly urls: string[];
  /** レコードが指す CID（= 本文の raw CID）。 */
  readonly cid: string;
}

/**
 * `/ipns/<name>` に署名済みレコードを、`/ipfs/<cid>` に本文を返す Gateway ダブル。
 *
 * @param docText `/ipfs/<cid>` が返す本文（CID は本文から導出する）。
 * @param recordSpec レコードの上書き（期限切れ・別鍵署名などの攻撃形状を作る）。
 * @param servedBody 実際に `/ipfs/<cid>` で返す本文（既定は `docText`。差し替え攻撃用）。
 */
export function ipnsGateway(
  seed: number,
  docText: string,
  recordSpec: IpnsRecordSpec = {},
  servedBody: string = docText,
): IpnsGateway {
  const cid = rawCidOf(docText);
  const name = ipnsNameOf(seed);
  const urls: string[] = [];
  const impl = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    urls.push(url);
    if (url.endsWith(`/ipns/${name}`)) {
      return new Response(ipnsRecordOf(seed, cid, recordSpec), {
        status: 200,
        headers: { 'content-type': 'application/vnd.ipfs.ipns-record' },
      });
    }
    if (url.endsWith(`/ipfs/${cid}`)) {
      return new Response(servedBody, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response('not found', { status: 404 });
  };
  return { fetch: impl as unknown as typeof fetch, urls, cid };
}

export { ipnsNameOf };
