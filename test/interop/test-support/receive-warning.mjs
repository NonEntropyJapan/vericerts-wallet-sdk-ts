import { run } from '../run-waltid-protocol.mjs';

const unexpectedCall = () => {
  throw new Error('malformed offer advanced past Receive');
};
const options = {
  createIssuerOfferImpl: async () => ({ offerUri: 'openid-credential-offer://' }),
  fetchImpl: unexpectedCall,
  createVerifierRequestImpl: unexpectedCall,
};
const first = await run(options);
const second = await run(options);
console.log(JSON.stringify([first, second]));
