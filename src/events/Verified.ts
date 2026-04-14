import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after email verification succeeds.
 */
export class Verified extends AtlexEvent {
  /**
   * @param payload - Verified user.
   */
  public constructor(public readonly payload: { readonly user: Authenticatable }) {
    super()
  }
}
