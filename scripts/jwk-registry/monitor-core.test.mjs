import { describe, expect, test } from 'bun:test';
import {
  computeIssHash,
  computeKidHash,
  GRACE_PERIOD_SECONDS,
  IDENTITY_PROVIDERS,
  modulusToLimbs,
  planActionsForIdp,
  selectRsaSigningKeys,
} from './monitor-core.mjs';

describe('modulusToLimbs', () => {
  test('121bit × 17 limb（下位 limb 先頭）に分割する', () => {
    // 2^121（limb 0 の直上）は limb[0]=0, limb[1]=1, 残り 0 になる境界値。
    const modulusInt = 1n << 121n;
    const n = Buffer.from(modulusInt.toString(16).padStart(32, '0'), 'hex').toString('base64url');
    const limbs = modulusToLimbs(n);
    expect(limbs.length).toBe(17);
    expect(limbs[0]).toBe(0n);
    expect(limbs[1]).toBe(1n);
    expect(limbs.slice(2).every((limb) => limb === 0n)).toBe(true);
  });

  test('任意の 2048bit modulus を可逆に分割する（round-trip）かつ各 limb は 121bit 未満', () => {
    // 決定論的な 256 バイト（2048bit）modulus。crypto.getRandomValues は使わず固定値にする。
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => (i * 7 + 3) % 256);
    const modulusInt = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
    const n = Buffer.from(bytes).toString('base64url');

    const limbs = modulusToLimbs(n);
    expect(limbs.length).toBe(17);
    for (const limb of limbs) {
      expect(limb >= 0n && limb < 1n << 121n).toBe(true);
    }
    const reconstructed = limbs.reduce((acc, limb, i) => acc + (limb << (121n * BigInt(i))), 0n);
    expect(reconstructed).toBe(modulusInt);
  });
});

describe('computeIssHash / computeKidHash', () => {
  // keccak256('')（Keccak-256, NIST SHA3 とは異なるパディング）の既知値。
  // Ethereum 系ライブラリで広く知られる定数（例: ethereumjs-util KECCAK256_NULL）。
  const KNOWN_KECCAK256_EMPTY =
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

  test('既知の Keccak-256 ベクタ（空文字列）と一致する', () => {
    expect(computeIssHash('')).toBe(KNOWN_KECCAK256_EMPTY);
    expect(computeKidHash('')).toBe(KNOWN_KECCAK256_EMPTY);
  });

  test('異なる iss / kid は異なるハッシュになる（衝突しない）', () => {
    expect(computeIssHash('https://accounts.google.com')).not.toBe(
      computeIssHash('https://appleid.apple.com'),
    );
    expect(computeKidHash('kid-a')).not.toBe(computeKidHash('kid-b'));
  });

  test('同じ入力には決定論的に同じハッシュを返す', () => {
    expect(computeIssHash('https://accounts.google.com')).toBe(
      computeIssHash('https://accounts.google.com'),
    );
  });
});

describe('IDENTITY_PROVIDERS', () => {
  test('Google と Apple の発行者と JWKS エンドポイントを含む', () => {
    expect(IDENTITY_PROVIDERS).toEqual([
      { iss: 'https://accounts.google.com', jwksUri: 'https://www.googleapis.com/oauth2/v3/certs' },
      { iss: 'https://appleid.apple.com', jwksUri: 'https://appleid.apple.com/auth/keys' },
    ]);
  });
});

describe('selectRsaSigningKeys', () => {
  test('kty=RSA かつ alg=RS256 のエントリだけを選ぶ', () => {
    const jwks = {
      keys: [
        { kty: 'RSA', alg: 'RS256', kid: 'rsa-ok', n: 'AA', use: 'sig' },
        { kty: 'EC', alg: 'ES256', kid: 'ec-key', n: 'BB' },
        { kty: 'RSA', alg: 'RS384', kid: 'rsa-wrong-alg', n: 'CC' },
        { kty: 'RSA', alg: 'RS256', n: 'DD' }, // kid 欠落
      ],
    };
    expect(selectRsaSigningKeys(jwks)).toEqual([{ kid: 'rsa-ok', n: 'AA' }]);
  });

  test('keys が無い / 配列でない JWKS は空配列を返す', () => {
    expect(selectRsaSigningKeys({})).toEqual([]);
    expect(selectRsaSigningKeys({ keys: 'not-an-array' })).toEqual([]);
  });
});

/** テスト用のチェーン状態スタブ。`modulusRegistered` は getModulusStatus の固定応答（既定 false = 常に新規）。 */
function createStubChainClient({
  modulusRegistered = false,
  modulusNotAfter = 0n,
  events = [],
  keyStates = {},
} = {}) {
  return {
    async getModulusStatus() {
      return { registered: modulusRegistered, notAfter: modulusNotAfter };
    },
    async getRegisteredEvents(issHash) {
      return events
        .filter((event) => event.issHash === issHash)
        .map(({ keyId, kidHash }) => ({ keyId, kidHash }));
    },
    async getKey(keyId) {
      return keyStates[keyId] ?? { registered: false, revoked: false, notAfter: 0n };
    },
  };
}

const IDP = { iss: 'https://accounts.google.com' };
const ISS_HASH = computeIssHash(IDP.iss);
const NOW = 1_800_000_000n;
/** 消失テスト用: 別の kid が JWKS に載っている（鍵が 0 件の異常応答ではない）状態。 */
const OTHER_LIVE_KEYS = [{ kid: 'other-live-kid', n: 'AQAB' }];

describe('planActionsForIdp', () => {
  test('未登録の kid は toRegister に計画される', async () => {
    const jwksKeys = [{ kid: 'new-kid', n: 'AQAB' }];
    const chainClient = createStubChainClient(); // 何も登録されていない
    const { toRegister, toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys,
      chainClient,
      now: NOW,
    });

    expect(toRegister).toHaveLength(1);
    expect(toRegister[0]).toMatchObject({ iss: IDP.iss, kid: 'new-kid', issHash: ISS_HASH });
    expect(toSetNotAfter).toHaveLength(0);
  });

  test('既に登録済みで JWKS にも残っている kid は何も計画しない', async () => {
    const jwksKeys = [{ kid: 'active-kid', n: 'AQAB' }];
    const kidHash = computeKidHash('active-kid');
    const chainClient = createStubChainClient({
      modulusRegistered: true,
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
      keyStates: { '0xkey1': { registered: true, revoked: false, notAfter: 0n } },
    });

    const { toRegister, toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys,
      chainClient,
      now: NOW,
    });
    expect(toRegister).toHaveLength(0);
    expect(toSetNotAfter).toHaveLength(0);
  });

  test('JWKS から消え、grace 未設定・未 revoke の kid は setNotAfter (now + 24h) を計画する', async () => {
    const kidHash = computeKidHash('vanished-kid');
    const chainClient = createStubChainClient({
      modulusRegistered: true,
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
      keyStates: { '0xkey1': { registered: true, revoked: false, notAfter: 0n } },
    });

    const { toRegister, toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys: OTHER_LIVE_KEYS,
      chainClient,
      now: NOW,
    });
    expect(toRegister).toHaveLength(0);
    expect(toSetNotAfter).toEqual([
      { iss: IDP.iss, keyId: '0xkey1', notAfter: NOW + GRACE_PERIOD_SECONDS },
    ]);
  });

  test('既に notAfter が設定済みの消失 kid には再発行しない（冪等性）', async () => {
    const kidHash = computeKidHash('already-graced-kid');
    const chainClient = createStubChainClient({
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
      keyStates: { '0xkey1': { registered: true, revoked: false, notAfter: NOW + 100n } },
    });

    const { toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys: OTHER_LIVE_KEYS,
      chainClient,
      now: NOW,
    });
    expect(toSetNotAfter).toHaveLength(0);
  });

  test('revoke 済みの消失 kid には setNotAfter を発行しない', async () => {
    const kidHash = computeKidHash('revoked-kid');
    const chainClient = createStubChainClient({
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
      keyStates: { '0xkey1': { registered: true, revoked: true, notAfter: 0n } },
    });

    const { toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys: OTHER_LIVE_KEYS,
      chainClient,
      now: NOW,
    });
    expect(toSetNotAfter).toHaveLength(0);
  });

  test('unregisterKey で訂正済み（registered=false）の消失候補には setNotAfter を発行しない', async () => {
    const kidHash = computeKidHash('corrected-kid');
    const chainClient = createStubChainClient({
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
      keyStates: { '0xkey1': { registered: false, revoked: false, notAfter: 0n } },
    });

    const { toSetNotAfter } = await planActionsForIdp({
      idp: IDP,
      jwksKeys: OTHER_LIVE_KEYS,
      chainClient,
      now: NOW,
    });
    expect(toSetNotAfter).toHaveLength(0);
  });
});

describe('planActionsForIdp の fail-closed', () => {
  const registeredKey = { registered: true, revoked: false, notAfter: 0n };

  test('選別後の鍵が 0 件（alg 欠落・keys 空）なら全鍵失効を計画せず例外を投げる', async () => {
    const chainClient = createStubChainClient({
      modulusRegistered: true,
      events: [
        { issHash: ISS_HASH, keyId: '0xkey1', kidHash: computeKidHash('a') },
        { issHash: ISS_HASH, keyId: '0xkey2', kidHash: computeKidHash('b') },
      ],
      keyStates: { '0xkey1': registeredKey, '0xkey2': registeredKey },
    });
    const algMissing = selectRsaSigningKeys({ keys: [{ kty: 'RSA', kid: 'a', n: 'AQAB' }] });
    for (const jwksKeys of [algMissing, selectRsaSigningKeys({ keys: [] })]) {
      await expect(
        planActionsForIdp({ idp: IDP, jwksKeys, chainClient, now: NOW }),
      ).rejects.toThrow('JWKS');
    }
  });

  test('grace 設定済みの kid が同一 modulus で JWKS に復帰したら setNotAfter(0) で復元する', async () => {
    const graced = NOW + GRACE_PERIOD_SECONDS;
    const chainClient = createStubChainClient({
      modulusRegistered: true,
      modulusNotAfter: graced,
      events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash: computeKidHash('back-kid') }],
      keyStates: { '0xkey1': { registered: true, revoked: false, notAfter: graced } },
    });
    const { toRestore, toSetNotAfter, toRegister } = await planActionsForIdp({
      idp: IDP,
      jwksKeys: [{ kid: 'back-kid', n: 'AQAB' }],
      chainClient,
      now: NOW,
    });
    expect(toRestore).toEqual([{ iss: IDP.iss, keyId: '0xkey1', kid: 'back-kid', notAfter: 0n }]);
    expect(toSetNotAfter).toHaveLength(0);
    expect(toRegister).toHaveLength(0);
  });

  test('復帰 kid でも revoke 済み・notAfter 未設定・別 modulus の鍵は復元しない', async () => {
    const graced = NOW + 100n;
    const kidHash = computeKidHash('back-kid');
    const cases = [
      { state: { registered: true, revoked: true, notAfter: graced }, statusNotAfter: graced },
      { state: { registered: true, revoked: false, notAfter: 0n }, statusNotAfter: 0n },
      {
        state: { registered: true, revoked: false, notAfter: graced },
        statusNotAfter: graced + 1n,
      },
    ];
    for (const { state, statusNotAfter } of cases) {
      const chainClient = createStubChainClient({
        modulusRegistered: true,
        modulusNotAfter: statusNotAfter,
        events: [{ issHash: ISS_HASH, keyId: '0xkey1', kidHash }],
        keyStates: { '0xkey1': state },
      });
      const { toRestore } = await planActionsForIdp({
        idp: IDP,
        jwksKeys: [{ kid: 'back-kid', n: 'AQAB' }],
        chainClient,
        now: NOW,
      });
      expect(toRestore).toHaveLength(0);
    }
  });
});
