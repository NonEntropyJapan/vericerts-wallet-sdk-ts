/** Issuer Metadata の実験的な公開 API。 */

export type { IssuerEndpoints } from '../../internal/auth/eudi/issuance/metadata.js';
export type { FetchLike } from '../../internal/fetch-di.js';

export { fetchIssuerMetadata } from '../experimental.js';
