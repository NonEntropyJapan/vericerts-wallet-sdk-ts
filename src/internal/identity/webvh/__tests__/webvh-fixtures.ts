/**
 * did:webvh テスト用のフィクスチャ生成ヘルパ。
 *
 * 実 Ed25519 鍵で proof を署名し、`createDidWebVh` / `updateDidWebVh` が生成する
 * proof 前エントリに proof を付与して、検証可能な DID Log（JSONL）を組み立てる。
 * モック/スタブではなく、本番の検証ロジックがそのまま通る本物の署名を作る。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { multibaseBase58Encode } from '../../multibase.js';
import {
  computeScid,
  deriveVersionId,
  entryWithoutProof,
  replaceInJson,
  SCID_PLACEHOLDER,
  versionNumberOf,
  type WebVhLogEntry,
  type WebVhProof,
} from '../codec.js';
import { documentHashOf, eddsaJcs2022HashData } from '../proof.js';

/** Ed25519 鍵ペア（テスト用）。 */
export interface TestKey {
  /** 秘密鍵（32B）。 */
  readonly secretKey: Uint8Array;
  /** Ed25519 Multikey（`z` + base58btc(0xed01 || pubkey)）。 */
  readonly multikey: string;
}

/** 指定の秘密鍵（シード）から決定的なテスト鍵を作る。 */
export function keyFromSeed(secretKey: Uint8Array): TestKey {
  const publicKey = ed25519.getPublicKey(secretKey);
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return { secretKey, multikey: multibaseBase58Encode(prefixed) };
}

/** 新しい Ed25519 テスト鍵を生成する。 */
export function generateKey(): TestKey {
  return keyFromSeed(ed25519.utils.randomSecretKey());
}

/**
 * proof 前エントリに、任意の署名関数で作った proof を付与する。
 *
 * 署名対象は本番 `verifyProofSignature` と同じ eddsa-jcs-2022 の `hashData`
 * （`SHA-256(JCS(proofConfig)) || SHA-256(JCS(proof を除いたエントリ))`）。
 * 不正・非正準な署名を差し込むテスト用に、署名生成を差し替えられるようにしている。
 */
export function attachProof(
  entry: WebVhLogEntry,
  key: TestKey,
  sign: (message: Uint8Array) => Uint8Array,
): WebVhLogEntry {
  const proofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    proofPurpose: 'assertionMethod',
    verificationMethod: `did:key:${key.multikey}#${key.multikey}`,
    // `challenge` は付けない（v1.0 の Authorized Keys は type / cryptosuite / proofPurpose / verificationMethod だけを要求する。
    // ログ位置は versionId を含む署名対象が束縛する）。
  };
  const message = eddsaJcs2022HashData(proofConfig, documentHashOf(entryWithoutProof(entry)));
  const proof: WebVhProof = { ...proofConfig, proofValue: multibaseBase58Encode(sign(message)) };
  return { ...entry, proof: [proof] };
}

/** proof 前エントリに、指定鍵で正規に署名した proof を付与する。 */
export function signEntry(entry: WebVhLogEntry, key: TestKey): WebVhLogEntry {
  return attachProof(entry, key, (message) => ed25519.sign(message, key.secretKey));
}

/**
 * `updateDidWebVh` を通さずに次版エントリ（proof 前）を組み立てる。
 *
 * ビルダーは `verifyChain` が拒否する行（失効行への追記・不正な versionTime）を生成時に拒否する
 *ので、検証側の拒否を確かめるテストは攻撃者/誤った実装が作る行をここで直接作る。
 * 失効は `parameters.deactivated`、時刻は `versionTime` をそのまま使う。`parameters` を省略すると前版の `updateKeys` を継続する。
 */
export function forgeAppendEntry(
  previousLog: readonly WebVhLogEntry[],
  state: WebVhLogEntry['state'],
  versionTime: string,
  parameters?: WebVhLogEntry['parameters'],
): WebVhLogEntry {
  const previous = previousLog[previousLog.length - 1] as WebVhLogEntry;
  const draft: WebVhLogEntry = {
    versionId: '',
    versionTime,
    parameters: parameters ?? { updateKeys: [...(previous.parameters.updateKeys ?? [])] },
    state,
  };
  const versionId = deriveVersionId(
    draft,
    versionNumberOf(previous.versionId) + 1,
    previous.versionId,
  );
  return { ...draft, versionId };
}

/** `forgeGenesis` の入力。 */
export interface ForgeGenesisOptions {
  /** 署名鍵（初版の updateKeys に入る）。 */
  readonly key: TestKey;
  /** 既定の parameters（`method` / `scid` / `updateKeys`）への上書き。値が `undefined` のキーは取り除く。 */
  readonly parameters?: Record<string, unknown>;
  readonly domain?: string;
  /** state への追加メンバ（`id` は SDK が設定する）。 */
  readonly state?: Record<string, unknown>;
  readonly versionTime?: string;
}

/**
 * `createDidWebVh` を通さずに、仕様どおりの手順（preliminary entry → SCID → 置換 → entryHash）で初版を組み立てる。
 * 生成側が拒否する parameters（未知の `method` など）を持つ初版を作り、検証側の拒否を確かめるために使う。
 * 返す初版は署名前。
 */
export function forgeGenesis(options: ForgeGenesisOptions): { did: string; entry: WebVhLogEntry } {
  const domain = options.domain ?? 'vericerts.io';
  const parameters: Record<string, unknown> = {
    method: 'did:webvh:1.0',
    scid: SCID_PLACEHOLDER,
    updateKeys: [options.key.multikey],
    ...options.parameters,
  };
  for (const [name, value] of Object.entries(parameters)) {
    if (value === undefined) {
      delete parameters[name];
    }
  }
  const stateFor = (id: string) => ({
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    ...options.state,
  });
  const preliminary = {
    versionId: SCID_PLACEHOLDER,
    versionTime: options.versionTime ?? new Date(Date.now() - 60_000).toISOString(),
    parameters,
    state: stateFor(`did:webvh:${SCID_PLACEHOLDER}:${domain}`),
  };
  const scid = computeScid(preliminary);
  const withScid = replaceInJson(preliminary, SCID_PLACEHOLDER, scid) as unknown as WebVhLogEntry;
  return {
    did: `did:webvh:${scid}:${domain}`,
    entry: { ...withScid, versionId: deriveVersionId(withScid, 1, scid) },
  };
}

/** エントリ配列を JSONL テキストにする。 */
export function toJsonl(entries: readonly WebVhLogEntry[]): string {
  return entries.map((entry) => JSON.stringify(entry)).join('\n');
}

const originalFetch = globalThis.fetch;

/** `globalThis.fetch` を指定 body を返すモックに差し替える。 */
export function mockFetchOnce(body: string, opts?: { status?: number; url?: string }): void {
  const status = opts?.status ?? 200;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const requestUrl =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    // `fetchDidLog` は DID Log の media type を検査する。Bun の `Response` は
    // 本文から `content-type` を補わないため、正当な DID Log 応答として明示する。
    const response = new Response(body, {
      status,
      headers: { 'content-type': 'application/jsonl' },
    });
    Object.defineProperty(response, 'url', {
      value: opts?.url ?? requestUrl,
      configurable: true,
    });
    return response;
  }) as unknown as typeof fetch;
}

/** fetch を必ず reject するモックに差し替える（ネットワークエラー再現）。 */
export function mockFetchReject(): void {
  globalThis.fetch = (async () => {
    throw new Error('network error');
  }) as unknown as typeof fetch;
}

/** `globalThis.fetch` を元に戻す。 */
export function restoreFetch(): void {
  globalThis.fetch = originalFetch;
}
