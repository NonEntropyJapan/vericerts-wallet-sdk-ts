/**
 * Wallet.presentPID の引数型 PresentOptions の公開面を検証する。
 * メインバレルから型を参照し、型付きのオプションを実際の提示呼び出しに渡す。
 */

import { describe, expect, it } from 'bun:test';
import type * as sdk from '../../index.js';
import { PID_VCT } from '../../internal/eudi/pid/index.js';
import {
  buildSdJwtVc,
  createStub,
  offerURI,
  RESPONSE_URI,
  requestURI,
  setupWallet,
  submittedVpToken,
  VALID_PID_CLAIMS,
} from '../../wallet/__tests__/eudi/eudi-fixtures.js';

describe('公開エクスポート: PresentOptions', () => {
  it('PresentOptions がメインバレルから型として名前で書け、presentPID の opts に渡せる', async () => {
    const sdJwt = buildSdJwtVc(PID_VCT, VALID_PID_CLAIMS);
    const stub = createStub(sdJwt);
    const wallet = await setupWallet({ eudiFetchImpl: stub.fetchImpl });
    await wallet.receivePID(offerURI());

    // `sdk.PresentOptions` が解決できないと（型が公開されていないと）ここで tsc が落ちる。
    // これがないと利用者は opts を型付きで組み立てられない。
    const opts: sdk.PresentOptions = {};
    const vp = await wallet.presentPID(requestURI(), ['family_name'], opts);

    // 型の再エクスポートだけでなく、実際に presentPID が動作すること。
    expect(vp.holder.startsWith('did:key:')).toBe(true);
    const submitted = stub.calls.find((call) => call.url === RESPONSE_URI);
    expect(submittedVpToken(submitted).startsWith(sdJwt.split('~')[0] ?? '')).toBe(true);
  });
});
