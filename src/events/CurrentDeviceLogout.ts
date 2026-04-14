import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired when the current session is destroyed during logout.
 */
export class CurrentDeviceLogout extends AtlexEvent {
  /**
   * @param payload - User and guard context.
   */
  public constructor(
    public readonly payload: { readonly guard: string; readonly user: Authenticatable },
  ) {
    super()
  }
}
