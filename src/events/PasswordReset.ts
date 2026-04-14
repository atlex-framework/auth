import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after a password is successfully reset.
 */
export class PasswordReset extends AtlexEvent {
  /**
   * @param payload - Affected user.
   */
  public constructor(public readonly payload: { readonly user: Authenticatable }) {
    super()
  }
}
