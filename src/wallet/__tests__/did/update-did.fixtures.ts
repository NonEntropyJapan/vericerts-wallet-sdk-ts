/**
 * `Wallet.updateDID`のテストが共有するフィクスチャ。
 *
 * 配線の回帰（`./wallet.update-did.test.ts`）と、own アクセサの `opts` によるドリフトの回帰
 * （`wallet.update-did-accessor-drift.test.ts`）が同じ Issuer 構成・同じスタブを使うため、
 * 組み立てをここへ集約する — 書き写すと、片方だけスタブの形が変わって「同じ経路のはずが別物を
 * 検証している」状態になる。
 */

import type { DIDDocument, DIDMethod, UpdateOptions } from '../../../internal/identity/did.js';

/** テスト対象のカスタム DID。 */
export const DID = 'did:stub:subject';

/** カスタムメソッドが解決する現行 DID Document。 */
export const CURRENT: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [{ id: `${DID}#key-1`, type: 'Multikey', controller: DID }],
  authentication: [`${DID}#key-1`],
  assertionMethod: [],
};

/** 本テストでは呼ばれない想定の `DIDMethod` メンバ用スタブ reject。 */
export const unused = (): Promise<never> =>
  Promise.reject(new Error('unused stub method called in test'));

/** テスト用ニーモニック（BIP-39 のテストベクタ）。`createDID('key')` はマスターシードを要する。 */
export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** `update` が受け取った `opts` を記録する更新対応プラグイン。 */
export function publishingMethod(): { method: DIDMethod; received: UpdateOptions[] } {
  const received: UpdateOptions[] = [];
  const method: DIDMethod = {
    method: () => 'stub',
    create: unused,
    resolve: () => Promise.resolve(CURRENT),
    update: (_did, opts) => {
      received.push(opts);
      // 実プラグインは公開後の Document を解決して返す。ここでは渡された Document をそのまま返す。
      return Promise.resolve(opts.document ?? CURRENT);
    },
    deactivate: unused,
  };
  return { method, received };
}
