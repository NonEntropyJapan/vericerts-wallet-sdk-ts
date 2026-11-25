/**
 * 分離型 Holder Service 向け KB-JWT テンプレートの取り違え・改竄検出のユニットテスト
 *（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `sd_hash` 不一致（提示部差し替え・別テンプレート由来の KB-JWT 流用）を合成時に検出すること。
 * - `nonce` / `audience` の取り違え・空値を検出すること。
 * - `typ` / `alg` が KB-JWT として不正な場合・構造不正の場合を拒否すること。
 *
 * 正常系は `key-binding.template.test.ts` を参照。
 */

import { describe, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  attachKeyBinding,
  attachKeyBindingSignature,
  createKeyBindingTemplate,
  type KeyBindingTemplate,
} from '../key-binding.js';
import { selectDisclosures } from '../sdjwt.js';
import {
  AUD,
  expectCode,
  IAT,
  issue,
  MISMATCHED_CRV_CNF,
  NONCE,
  SESSION_ALG,
  signAsSession,
  toCompactKbJwt,
} from './key-binding.fixtures.js';

/** 開示クレームだけが異なるテンプレートを作る。 */
function templateFor(disclosedClaims: readonly string[]) {
  return createKeyBindingTemplate(issue(), {
    alg: SESSION_ALG,
    nonce: NONCE,
    audience: AUD,
    disclosedClaims,
    iatSeconds: IAT,
  });
}

/** テンプレートの header / payload に余剰クレームを混ぜ、Session 鍵で正しく署名した KB-JWT を組む。 */
function forgeKbJwt(
  template: KeyBindingTemplate,
  extra: { readonly header?: object; readonly payload?: object },
): string {
  const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
  const signingInput = `${b64({ ...template.header, ...extra.header })}.${b64({
    ...template.payload,
    ...extra.payload,
  })}`;
  return toCompactKbJwt(signingInput, signAsSession(signingInput));
}

describe('分離型 Holder Service: nonce / audience の取り違え検出', () => {
  it('nonce / audience が空文字列なら 3012 で拒否する（取り違え・未設定の検出）', () => {
    const sdJwt = issue();
    expectCode(
      () =>
        createKeyBindingTemplate(sdJwt, {
          alg: SESSION_ALG,
          nonce: '',
          audience: AUD,
          iatSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
    expectCode(
      () =>
        createKeyBindingTemplate(sdJwt, {
          alg: SESSION_ALG,
          nonce: NONCE,
          audience: '',
          iatSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('別 nonce / 別 audience で署名された KB-JWT の流用を拒否する（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const template = createKeyBindingTemplate(presented, {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });

    for (const replay of [
      { nonce: 'other-nonce', audience: AUD },
      { nonce: NONCE, audience: 'https://attacker.example/client' },
    ]) {
      const replayed = createKeyBindingTemplate(presented, {
        alg: SESSION_ALG,
        nonce: replay.nonce,
        audience: replay.audience,
        iatSeconds: IAT,
      });
      const kbJwt = toCompactKbJwt(replayed.signingInput, signAsSession(replayed.signingInput));
      expectCode(() => attachKeyBinding(template, kbJwt), ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  });

  it('nonce と audience を取り違えて署名された KB-JWT を拒否する（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const template = createKeyBindingTemplate(presented, {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    // nonce と audience を入れ替えて組んだテンプレートで署名した KB-JWT。
    const swapped = createKeyBindingTemplate(presented, {
      alg: SESSION_ALG,
      nonce: AUD,
      audience: NONCE,
      iatSeconds: IAT,
    });
    const kbJwt = toCompactKbJwt(swapped.signingInput, signAsSession(swapped.signingInput));

    expectCode(() => attachKeyBinding(template, kbJwt), ErrorCodes.HOLDER_BIND_MISMATCH);
  });
});

describe('分離型 Holder Service: sd_hash 不一致の検出', () => {
  it('提示部を差し替えたテンプレートへの合成を sd_hash 不一致で拒否する（3012）', () => {
    const original = templateFor(['name']);
    const other = templateFor(['name', 'email']);

    // Agent は original の signingInput に署名したが、Holder Service 側で提示部だけが
    // 別の（より多くを開示する）ものに差し替えられた状況を再現する。
    const tampered = { ...original, presentation: other.presentation };
    const signature = signAsSession(original.signingInput);

    expectCode(
      () => attachKeyBindingSignature(tampered, signature),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('別テンプレート由来の KB-JWT の流用を sd_hash 不一致で拒否する（3012）', () => {
    const original = templateFor(['name']);
    const other = templateFor(['name', 'email']);

    // other 用に署名された KB-JWT を original の提示部へ流用する。
    const otherKbJwt = toCompactKbJwt(other.signingInput, signAsSession(other.signingInput));

    expectCode(() => attachKeyBinding(original, otherKbJwt), ErrorCodes.HOLDER_BIND_MISMATCH);
  });
});

describe('分離型 Holder Service: KB-JWT 構造の検証', () => {
  it('typ / alg が KB-JWT として不正なら拒否する（3012）', () => {
    const template = templateFor(['name']);
    const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
    const signature = Buffer.from(signAsSession(template.signingInput)).toString('base64url');

    for (const header of [
      { alg: SESSION_ALG, typ: 'JWT' },
      { alg: 'ES256', typ: 'kb+jwt' },
    ]) {
      const kbJwt = `${b64(header)}.${b64(template.payload)}.${signature}`;
      expectCode(() => attachKeyBinding(template, kbJwt), ErrorCodes.HOLDER_BIND_MISMATCH);
    }
  });

  it('KB-JWT の構造が不正なら 3010 で拒否する', () => {
    const template = templateFor(['name']);
    expectCode(() => attachKeyBinding(template, 'not-a-jwt'), ErrorCodes.SIG_INVALID);
  });
});

describe('分離型 Holder Service: 署名対象（signingInput）の完全一致検証', () => {
  // `verifySignature: false` で検証するのは、署名検証ではなく signingInput の一致検証が
  // 効いていることを示すため（KB-JWT 自体は Session 鍵で正しく署名されている）。
  it('payload に余剰クレーム（exp）を混ぜた KB-JWT を拒否する（3012）', () => {
    const template = templateFor(['name']);
    const kbJwt = forgeKbJwt(template, { payload: { exp: IAT + 300 } });
    expectCode(
      () => attachKeyBinding(template, kbJwt, { verifySignature: false }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('header に余剰クレーム（kid）を混ぜた KB-JWT を拒否する（3012）', () => {
    const template = templateFor(['name']);
    const kbJwt = forgeKbJwt(template, { header: { kid: 'agent-session-1' } });
    expectCode(
      () => attachKeyBinding(template, kbJwt, { verifySignature: false }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });
});

describe('分離型 Holder Service: cnf.jwk と alg の曲線不一致', () => {
  it('曲線不一致でも 2001 を漏らさず 3012 へ正規化する', () => {
    // cnf は P-256 鍵だが、テンプレートの alg は ES256K（secp256k1）。
    const template = createKeyBindingTemplate(issue(MISMATCHED_CRV_CNF), {
      alg: SESSION_ALG,
      nonce: NONCE,
      audience: AUD,
      disclosedClaims: ['name'],
      iatSeconds: IAT,
    });
    expectCode(
      () => attachKeyBindingSignature(template, signAsSession(template.signingInput)),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });
});
