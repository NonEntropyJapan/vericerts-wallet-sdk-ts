/**
 * did:pkh / did:ethr の controller 鍵の署名ラウンドトリップ（`alg: "ES256K-R"`）。
 *
 * 取り込んだペルソナの署名鍵（`resolvePersonaSigner`）で VP / VC / SIOPv2 id_token / signMessage を署名し、SDK の検証経路で
 * 検証する（共有スイート `defineRoundtripSuite`）。検証鍵は DID Document の `blockchainAccountId` から組むアドレス鍵。
 */

import { MethodPkh } from '../../../../identity/pkh/method-pkh.js';
import { ethereumAddressOfJwk } from '../../../../keymanager/eip191.js';
import { ethrDocument, externalKey, newWorld, stubMethod } from '../fixtures.js';
import { type Case, defineRoundtripSuite, imported } from '../roundtrip-suite.js';

const SECP_KEY = externalKey('secp256k1', 21);
const ADDRESS = ethereumAddressOfJwk(SECP_KEY.publicKeyJwk.x, SECP_KEY.publicKeyJwk.y) as string;

const CASES: readonly Case[] = [
  {
    name: 'did:pkh（blockchainAccountId のみ、secp256k1 の EIP-191 / ES256K-R。標準外の例外）',
    alg: 'ES256K-R',
    setup: async () => {
      const world = await newWorld({ methods: [new MethodPkh()] });
      return imported(world, `did:pkh:eip155:1:${ADDRESS}`, SECP_KEY.privateKeyJwk);
    },
  },
  {
    name: 'did:ethr controller（#controller の blockchainAccountId、ES256K-R。標準外の例外）',
    alg: 'ES256K-R',
    setup: async () => {
      const { did, document } = ethrDocument(ADDRESS, []);
      const world = await newWorld({ methods: [stubMethod('ethr', { [did]: document })] });
      return imported(world, did, SECP_KEY.privateKeyJwk);
    },
  },
];

defineRoundtripSuite(CASES);
