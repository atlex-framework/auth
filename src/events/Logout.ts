import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after logout completes.
 */
export class Logout extends AtlexEvent {
  /**
   * @param payload - Guard and user that was logged out.
   */
  public constructor(
    public readonly payload: { readonly guard: string; readonly user: Authenticatable | null },
  ) {
    super()
  }
}
