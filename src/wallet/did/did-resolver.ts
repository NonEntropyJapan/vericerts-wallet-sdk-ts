/**
 * DID Resolver の構築（`createWallet` と、Wallet を作らずに DID 解決だけを行う呼び出し側の共通経路）。
 *
 * {@link createDidResolver} と `createWallet` は同じ登録処理を使うため、同じオプションを渡せば
 * 同じ DID メソッドを解決できる。
 */

import { MethodCheqd } from '../../internal/identity/cheqd/method-cheqd.js';
import { MethodEbsi } from '../../internal/identity/ebsi/method-ebsi.js';
import { MethodEthr } from '../../internal/identity/ethr/method-ethr.js';
import { MethodIon } from '../../internal/identity/ion/method-ion.js';
import { MethodIpid } from '../../internal/identity/ipid/method-ipid.js';
import { MethodJwk } from '../../internal/identity/jwk/method-jwk.js';
import { MethodJwt } from '../../internal/identity/jwt/method-jwt.js';
import { MethodKey } from '../../internal/identity/method-key.js';
import { NO_RESOLUTION_CACHE } from '../../internal/identity/network/resolution-cache.js';
import { MethodPeer } from '../../internal/identity/peer/method-peer.js';
import { MethodPkh } from '../../internal/identity/pkh/method-pkh.js';
import { MethodPlc } from '../../internal/identity/plc/method-plc.js';
import { registerResourceBoundWebMethods } from '../../internal/identity/resolution-resources/resource-bound-methods.js';
import {
  type DidResolutionResources,
  readDidResolutionResources,
} from '../../internal/identity/resolution-resources/resources.js';
import { Resolver } from '../../internal/identity/resolver.js';
import { MethodWeb, NO_DID_WEB_CACHE } from '../../internal/identity/web/method-web.js';
import { MethodWebVh } from '../../internal/identity/webvh/method-webvh.js';
import { ownProperty } from '../../internal/prototype-safety/own-property.js';
import type { DidNodeUrls } from './did-node-urls.js';

/**
 * {@link createDidResolver} のオプション。`WalletOptions` の DID 解決に関わるフィールドと同じ名前・同じ意味である
 * （`createWallet` は `WalletOptions` をそのまま渡すので、型が食い違えばコンパイルが通らない）。
 *
 * いずれも**呼び出し側が選んだ接続先**で、DID 文字列からは導出しない（信頼の根は指定した RPC / Gateway /
 * ノードの運営者になる）。値は own プロパティとしてだけ読む（`Object.prototype` 汚染で省略した接続先が攻撃者の
 * エンドポイントに化けない）。
 *
 * `WalletOptions` を import しないのは、型の依存だけでも Wallet ファサード全体（鍵管理・AA・委譲）を引き込むため
 * （拡張機能は本モジュールだけをバンドル・型検査する）。
 */
export interface DidResolverOptions {
  /**
   * did:ethr 解決用のチェーン ID → RPC URL マップ。マップに無いチェーンの did:ethr は `DID_NOT_FOUND`（`2003`）になる。
   */
  readonly rpcUrls?: Readonly<Record<number, string>>;
  /** did:ipid の DID Document 取得に使う IPFS Gateway URL。既定は `https://ipfs.io`。 */
  readonly ipfsGatewayUrl?: string;
  /** did:ipid の公開（create / update）に用いる IPFS HTTP API URL（省略時は既定 `http://localhost:5001`）。 */
  readonly ipfsApiUrl?: string;
  /** did:ebsi / did:ion / did:cheqd の解決先 URL（`https:` のみ）。未指定のメソッドの解決は `2002` で失敗する。 */
  readonly didNodeUrls?: DidNodeUrls;
}

/** `buildDidResolver` の戻り値。did:key の Document 生成に使う `MethodKey` も併せて返す。 */
export interface ResolverSetup {
  /** 全 DID メソッドを登録済みの Resolver。 */
  readonly resolver: Resolver;
  /** did:key メソッド（DID Document 生成用に再利用する）。 */
  readonly method: MethodKey;
}

/**
 * `opts.rpcUrls`（chainId → RPC URL）を own 限定で読む（未指定は空マップ）。
 *
 * did:ethr の解決（{@link buildDidResolver}）と controller 検出（`createWallet` の eventSource）が同じ
 * RPC マップを共有するための共通読み出し。
 */
export function readRpcUrls(opts: DidResolverOptions): Readonly<Record<number, string>> {
  return ownProperty<Readonly<Record<number, string>>>(opts, 'rpcUrls') ?? {};
}

/**
 * 全 DID メソッドを登録した Resolver を構築する（`createWallet` 用。did:key メソッドも返す）。
 *
 * did:ethr は `opts.rpcUrls`（chainId → RPC URL）で解決し（未設定チェーンは DID_NOT_FOUND）、
 * did:ipid は IPFS Gateway / API で解決・公開する（既定 URL は {@link DidResolverOptions} を参照）。
 * did:ebsi / did:ion / did:cheqd は `opts.didNodeUrls` の EBSI / Sidetree ノード / cheqd リゾルバーで解決する（未指定のメソッドは登録せず
 * `resolveDID` は `2002`）。
 *
 * @param opts DID 解決のオプション（rpcUrls / IPFS URL / didNodeUrls を参照する）。
 * @returns 登録済み Resolver と did:key メソッド。
 */
export function buildDidResolver(
  opts: DidResolverOptions,
  resources?: { readonly webResolutionResources?: DidResolutionResources },
): ResolverSetup {
  const webResources = readDidResolutionResources(resources);
  // 呼び出しオプションは own 限定で読む（`Object.prototype` 汚染で省略した引数が攻撃者の RPC /
  // IPFS ゲートウェイに化けるのを防ぐ）。省略分は `MethodIpid` 側の既定へ落ちる。
  const ipfsGatewayUrl = ownProperty<string>(opts, 'ipfsGatewayUrl');
  const ipfsApiUrl = ownProperty<string>(opts, 'ipfsApiUrl');
  const nodeUrls = ownProperty<DidNodeUrls>(opts, 'didNodeUrls');
  const ebsiApiUrl = nodeUrls === undefined ? undefined : ownProperty<string>(nodeUrls, 'ebsi');
  const ionNodeUrl = nodeUrls === undefined ? undefined : ownProperty<string>(nodeUrls, 'ion');
  const cheqdResolverUrl =
    nodeUrls === undefined ? undefined : ownProperty<string>(nodeUrls, 'cheqd');
  const method = new MethodKey();
  const resolver = new Resolver();
  resolver.register(method);
  if (webResources === undefined) {
    resolver.register(new MethodWeb());
    resolver.registerUncached(new MethodWeb({ cache: NO_DID_WEB_CACHE }));
    resolver.register(new MethodWebVh());
  } else {
    registerResourceBoundWebMethods(resolver, webResources);
  }
  resolver.register(new MethodJwk());
  resolver.register(new MethodPeer());
  resolver.register(new MethodPkh());
  resolver.register(new MethodPlc());
  resolver.register(new MethodEthr({ rpcUrls: readRpcUrls(opts) }));
  resolver.register(new MethodJwt());
  resolver.register(new MethodIpid({ gatewayUrl: ipfsGatewayUrl, apiUrl: ipfsApiUrl }));
  // did:ebsi は解決先ノードが DID から決まらないため、指定されたときだけ登録する。
  if (ebsiApiUrl !== undefined) {
    resolver.register(new MethodEbsi({ apiUrl: ebsiApiUrl }));
    resolver.registerUncached(new MethodEbsi({ apiUrl: ebsiApiUrl, cache: NO_RESOLUTION_CACHE }));
  }
  // did:ion も同様（解決のみ。アンカー前の long-form は既定で採用しない）。
  if (ionNodeUrl !== undefined) {
    resolver.register(new MethodIon({ nodeUrl: ionNodeUrl }));
    resolver.registerUncached(new MethodIon({ nodeUrl: ionNodeUrl, cache: NO_RESOLUTION_CACHE }));
  }
  // did:cheqd も同様（解決のみ。リゾルバー運営者が信頼の前提になるため既定では登録しない）。
  if (cheqdResolverUrl !== undefined) {
    resolver.register(new MethodCheqd({ resolverUrl: cheqdResolverUrl }));
    resolver.registerUncached(
      new MethodCheqd({ resolverUrl: cheqdResolverUrl, cache: NO_RESOLUTION_CACHE }),
    );
  }
  return { resolver, method };
}

/**
 * `Wallet.resolveDID` と同じ DID メソッド一式を登録した {@link Resolver} を、`Wallet` を作らずに構築する。
 *
 * 登録されるメソッドとオプションの意味は `createWallet` と同一である（同じ {@link buildDidResolver} を通る）:
 * did:key / jwk / web / peer / pkh / plc / ethr / jwt / webvh / ipid は常に登録し、did:ebsi / ion / cheqd は
 * `didNodeUrls` で当該メソッドの URL を渡したときだけ登録する（未指定は `2002`）。did:ethr は `rpcUrls` に無い
 * チェーンを `DID_NOT_FOUND`（`2003`）で拒否し、did:ipid は `ipfsGatewayUrl` 省略時に既定 `https://ipfs.io` を使う。
 * `resolver.resolve(did)` は `Wallet.resolveDID` と同じエラーコード（`2001` / `2002` / `2003` / `2010`）で失敗する。
 *
 * 接続先は呼び出し側が組み立てる信頼の前提である。**DID の持ち主・dApp・VC の発行者が選べる入力から組み立てて
 * はならない**。
 *
 * 生成した Resolver はメソッドごとの状態（did:web のキャッシュ等）を持つので、呼び出しごとに作り直さず
 * 使い回すこと。DID メソッドを差し替えたい場合は `resolver.register(method)`（同名は上書き）を使う。
 *
 * @param opts DID 解決のオプション（省略時は接続先なし: did:ethr は全チェーン `2003`、did:ipid は既定 Gateway）。
 * @param resources 任意の共有本文予約handle。did:web/webvhだけに適用し、省略時は従来どおり制限を追加しない。
 * @returns 登録済みの Resolver。
 * @throws TypeError for malformed resource options or a handle not created by this SDK instance.
 */
export function createDidResolver(
  opts: DidResolverOptions = {},
  resources?: { readonly webResolutionResources?: DidResolutionResources },
): Resolver {
  return buildDidResolver(opts, resources).resolver;
}
