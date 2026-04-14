import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after a password reset notification is dispatched.
 */
export class PasswordResetLinkSent extends AtlexEvent {
  /**
   * @param payload - User that received the link.
   */
  public constructor(public readonly payload: { readonly user: Authenticatable }) {
    super()
  }
}
