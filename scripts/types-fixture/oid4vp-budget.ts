// 公開 /oid4vp だけで DCQL の共有予算を作り、両評価 API に渡す consumer。
import {
  createDcqlWorkBudget,
  type DcqlWorkBudget,
  evaluateDcql,
  findMatchingCredentialIndexes,
} from '@vericerts/vericerts-wallet-sdk/oid4vp';

const budget: DcqlWorkBudget = createDcqlWorkBudget();
const fromFactory: ReturnType<typeof createDcqlWorkBudget> = budget;
const fromAlias: DcqlWorkBudget = fromFactory;
fromAlias.remaining = 10;
fromAlias.exhausted = false;

const query = { credentials: [{ id: 'degree', format: 'jwt_vc_json' }] };
const credentials = [{ id: 'vc', format: 'jwt_vc_json', claims: {} }];
evaluateDcql(query, credentials, fromAlias);
findMatchingCredentialIndexes(query, credentials, fromFactory);
