/**
 * did:webvh の proof のログ位置束縛・versionTime のテストが共有するログの組み立てヘルパ。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { multibaseBase58Encode } from '../../../multibase.js';
import {
  deriveVersionId,
  entryWithoutProof,
  type WebVhLogEntry,
  type WebVhProof,
} from '../../codec.js';
import { createDidWebVh, updateDidWebVh } from '../../method-webvh.js';
import { documentHashOf, eddsaJcs2022HashData } from '../../proof.js';
import { signEntry, type TestKey } from '../webvh-fixtures.js';

export const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);

const VM_A = 'did:webvh:placeholder#A';

/** 失効前に有効だった検証メソッド `#A` を持つ初版を作る。 */
export function buildGenesis(key: TestKey): { did: string; signedGenesis: WebVhLogEntry } {
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: [key.multikey],
    document: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        {
          id: VM_A,
          type: 'Multikey',
          controller: 'did:webvh:placeholder',
          publicKeyMultibase: 'zCOMPROMISED',
        },
      ],
      authentication: [VM_A],
      assertionMethod: [VM_A],
    },
  });
  return { did, signedGenesis: signEntry(logEntry, key) };
}

/** `#A` を含まない（失効・ローテーション後の）署名済み 2 版目を作る。 */
export function buildRotatedV2(did: string, genesis: WebVhLogEntry, key: TestKey): WebVhLogEntry {
  const v2 = updateDidWebVh({
    previousLog: [genesis],
    state: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    },
  });
  return signEntry(v2, key);
}

/** 任意の proofConfig で正規に署名した proof を付与する（位置束縛の各要素を個別に外す用）。 */
export function signWithConfig(
  entry: WebVhLogEntry,
  key: TestKey,
  config: Record<string, unknown>,
): WebVhLogEntry {
  const proofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    proofPurpose: 'assertionMethod',
    verificationMethod: `did:key:${key.multikey}#${key.multikey}`,
    ...config,
  };
  const message = eddsaJcs2022HashData(proofConfig, documentHashOf(entryWithoutProof(entry)));
  const proof: WebVhProof = {
    ...proofConfig,
    proofValue: multibaseBase58Encode(ed25519.sign(message, key.secretKey)),
  };
  return { ...entry, proof: [proof] };
}

/** 署名済みエントリの本体・proof を保ち、`versionId` だけを `number` 版目（直前は `previousVersionId`）として再計算する。 */
export function repositioned(
  entry: WebVhLogEntry,
  number: number,
  previousVersionId: string,
): WebVhLogEntry {
  const draft: WebVhLogEntry = { ...entry, versionId: '' };
  return { ...draft, versionId: deriveVersionId(draft, number, previousVersionId) };
}

/** 初版の本体と proof を複製し、`versionId` だけ 3 版目として再計算した再送エントリを作る（鍵なしの攻撃者の操作）。 */
export function buildReplay(key: TestKey) {
  const { did, signedGenesis } = buildGenesis(key);
  const signedV2 = buildRotatedV2(did, signedGenesis, key);
  return {
    did,
    signedGenesis,
    signedV2,
    replayed: repositioned(signedGenesis, 3, signedV2.versionId),
  };
}
