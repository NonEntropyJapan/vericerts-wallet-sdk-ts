/**
 * Lend テストが共有するお膳立て（期限解釈のテストを別ファイルへ分けたときに切り出した）。
 *
 * 同じ貸主・受取人・基準時刻を 2 ファイルに書き写すと、片方だけ直して食い違う。
 */

import { createLend } from '../lend.js';
import { testSigner } from './fixtures.js';

export const LENDER_DID = 'did:peer:2.Lender';
export const RECIPIENT_DID = 'did:peer:2.Tablet';
export const NOW = Date.parse('2026-05-01T00:00:00Z');
export const FUTURE = '2026-06-01T00:00:00Z';
export const PAST = '2026-04-01T00:00:00Z';

export function lender() {
  return { did: LENDER_DID, signer: testSigner('did:key:lender#0') };
}

/** 指定 ID・期限の Lend トークンを作る（署名は `createLend` 由来。期限は上書き可）。 */
export function lendToken(id: string, validUntil: string) {
  const token = createLend(
    ['vc-1'],
    FUTURE,
    RECIPIENT_DID,
    lender(),
    {},
    { now: () => NOW, generateId: () => id },
  );
  return { ...token, valid_until: validUntil };
}
