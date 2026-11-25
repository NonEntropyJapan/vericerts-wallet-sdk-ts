/**
 * `Wallet.updateDID` の `opts` を own アクセサで実装した場合の回帰（GDPR Art.9）。
 *
 * `opts` の各メンバを「差分適用のとき」と「プラグインへ委譲するとき」の 2 回読むと、読むたびに
 * 違う値を返すアクセサによって **Art.9 ガードが見た値と公開される値が別物になる**。差分を自分で
 * 適用するプラグイン（`opts.document` を見ないもの。did:ipid 系がその形）は、検査を一度も通って
 * いない特別カテゴリ属性をそのままオンチェーン / DID Log へ載せられてしまう。
 *
 * 配線そのもの（解決 → 差分適用 → ガード → 公開委譲 → 控えの整合）は
 * `./wallet.update-did.test.ts` が持つ。本ファイルは「1 度だけ読む」という不変条件だけを押さえる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import type { Service } from '../../../internal/identity/did.js';
import { MemoryStorage } from '../../../storage/storage.js';
import type { UpdateDIDOptions } from '../../did/options.js';
import { createWallet } from '../../factory.js';
import { CURRENT, DID, publishingMethod } from './update-did.fixtures.js';

/**
 * 読むたびに別の `serviceEndpoint` を返す `addService` アクセサを持つ `opts` を作る。
 *
 * @param first 1 回目の読みが返す `serviceEndpoint`。
 * @param rest 2 回目以降の読みが返す `serviceEndpoint`。
 */
function driftingAddService(
  first: Readonly<Record<string, unknown>>,
  rest: Readonly<Record<string, unknown>>,
): UpdateDIDOptions {
  let reads = 0;
  return {
    get addService(): Service {
      reads += 1;
      return {
        id: `${DID}#svc`,
        type: 'Example',
        serviceEndpoint: reads === 1 ? first : rest,
      };
    },
  } as UpdateDIDOptions;
}

const BENIGN = { url: 'https://example.test/benign' };
// SDK が書き込みを拒否する特別カテゴリ属性名。DID Document は公開されると取り消せない。
const SPECIAL_CATEGORY = { healthData: 'https://example.test/records' };

describe('Wallet.updateDID: own アクセサの opts', () => {
  it('プラグインへ渡る差分は Art.9 ガードを通った 1 回目の値と一致する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    await wallet.updateDID(DID, driftingAddService(BENIGN, SPECIAL_CATEGORY));

    // プラグインが受け取る差分も、公開される Document も、ガードが見た 1 回目の値であること。
    expect(received[0]?.addService?.serviceEndpoint).toEqual(BENIGN);
    expect(received[0]?.document?.service?.[0]?.serviceEndpoint).toEqual(BENIGN);
  });

  // **回帰を担うのは上のケースだけ**である（修正前は `pluginOptions(opts, next)` がアクセサを
  // 再読し、プラグインへ `SPECIAL_CATEGORY` を転送していた）。こちらは修正の前後どちらでも通る
  // —— 修正前も `applyDidDocumentUpdate` が初回の読み取りを消費し、いずれにせよガードが投げたためで、
  // 固定しているのは「ガードの判定基準は 1 回目の読み」という周辺契約のほうである。
  it('1 回目の読みが特別カテゴリ属性なら、後続の読みが無害でも 10601 で止まる', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    const { method, received } = publishingMethod();
    wallet.registerDIDMethod(method);

    await expect(
      wallet.updateDID(DID, driftingAddService(SPECIAL_CATEGORY, BENIGN)),
    ).rejects.toThrow(new VericertsError(ErrorCodes.GDPR_SPECIAL_CATEGORY_ON_CHAIN));
    // 公開委譲へは 1 度も進まない。
    expect(received).toHaveLength(0);
    // 現行 Document は据え置き（ガードは公開前に止める）。
    expect(CURRENT.service).toBeUndefined();
  });
});
