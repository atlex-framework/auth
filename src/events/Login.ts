import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after a successful interactive login.
 */
export class Login extends AtlexEvent {
  /**
   * @param payload - Guard and authenticated principal.
   */
  public constructor(
    public readonly payload: {
      readonly guard: string
      readonly user: Authenticatable
      readonly remember: boolean
    },
  ) {
    super()
  }
}
