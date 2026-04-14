import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired when a new user registers (application hook).
 */
export class Registered extends AtlexEvent {
  /**
   * @param payload - New user record.
   */
  public constructor(public readonly payload: { readonly user: Authenticatable }) {
    super()
  }
}
