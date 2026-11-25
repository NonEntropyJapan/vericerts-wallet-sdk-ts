/**
 * 用途別 entry `vericerts-wallet-sdk/aa`。
 *
 * サブパス専用バレル。利用契約レジストリでこの entry に割り当てられた、Passkey による
 * UserOperation 署名の面だけを公開する。`index.ts` には本バレルを載せない。
 * 内部バレル `internal/aa/index.ts` を経由せず定義元を直接指すのは、そちらが引く
 * `viem/account-abstraction` / `permissionless`（UserOpHash 計算・Bundler 送信）を、ESM 出力
 * （`--splitting`）で本 entry のチャンクへ入れないためである。CJS は全サーフェス共有の
 * `_shared.cjs` を読むので、この分離は効かない。
 */

export {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  type UserOperationV07,
} from '../internal/aa/types.js';
export {
  signUserOpWithPasskey,
  type WebAuthnAssertion,
} from '../internal/aa/webauthn-signature.js';
