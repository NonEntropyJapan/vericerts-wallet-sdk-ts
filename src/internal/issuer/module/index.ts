/**
 * Issuer facade（`IssuerModule`）のサブバレル。
 *
 * VC の組み立てと失効管理の facade（`IssuerModule` / `IssueOptions`）を
 * まとめて再エクスポートする。運用ヘルパー層（`StatusListManager` 等）は親の
 * `issuer/index.ts` が再エクスポートする。
 */

export type { IssueOptions, StatusListType, VCFormat } from './issue-options.js';
export {
  type IssuedStatusEntry,
  IssuerModule,
  type IssuerModuleOptions,
  type TokenStatusPurpose,
} from './issuer-module.js';
