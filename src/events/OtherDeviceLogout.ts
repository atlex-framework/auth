import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired when other devices are logged out (e.g. password change).
 */
export class OtherDeviceLogout extends AtlexEvent {
  /**
   * @param payload - User context.
   */
  public constructor(
    public readonly payload: { readonly guard: string; readonly user: Authenticatable },
  ) {
    super()
  }
}
