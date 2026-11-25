/**
 * did:ion の未公開（`published: false`）の採用条件。
 *
 * 採れるのは long-form だけで、short-form は `allowUnpublished` でも `2003`（`ion_unpublished`）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import {
  expectRejects,
  jsonReply,
  recordingFetch,
} from '../../__tests__/network-method.fixtures.js';
import { MethodIon, resolveDidIon } from '../method-ion.js';
import { ionResponse, makeIonCreate, NODE_URL } from './ion.fixtures.js';

const create = makeIonCreate();

describe('did:ion 未公開の採用条件', () => {
  it('short-form の published: false は allowUnpublished でも 2003（ion_unpublished）', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(ionResponse(create.shortForm, create, { published: false })),
    );
    await expectRejects(
      resolveDidIon(create.shortForm, { nodeUrl: NODE_URL, allowUnpublished: true, fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
      'ion_unpublished',
    );
    await expectRejects(
      new MethodIon({ nodeUrl: NODE_URL, allowUnpublished: true, fetchFn }).resolve(
        create.shortForm,
      ),
      ErrorCodes.DID_NOT_FOUND,
      'ion_unpublished',
    );
  });

  it('long-form の published: false は allowUnpublished のときだけ採用する', async () => {
    const { fetchFn } = recordingFetch(() =>
      jsonReply(ionResponse(create.longForm, create, { published: false })),
    );
    await expectRejects(
      resolveDidIon(create.longForm, { nodeUrl: NODE_URL, fetchFn }),
      ErrorCodes.DID_NOT_FOUND,
      'ion_unpublished',
    );
    const { document, metadata } = await resolveDidIon(create.longForm, {
      nodeUrl: NODE_URL,
      allowUnpublished: true,
      fetchFn,
    });
    expect(document.id).toBe(create.longForm);
    expect(metadata.published).toBe(false);
  });
});
