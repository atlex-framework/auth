import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired when a user is resolved from session or token without a fresh login.
 */
export class Authenticated extends AtlexEvent {
  /**
   * @param payload - Guard and resolved user.
   */
  public constructor(
    public readonly payload: { readonly guard: string; readonly user: Authenticatable },
  ) {
    super()
  }
}
