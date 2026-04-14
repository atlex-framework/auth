import { AtlexEvent } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

/**
 * Fired after a failed credential check.
 */
export class Failed extends AtlexEvent {
  /**
   * @param payload - Guard and credential context.
   */
  public constructor(
    public readonly payload: {
      readonly guard: string
      readonly credentials: Record<string, unknown>
      readonly user?: Authenticatable
    },
  ) {
    super()
  }
}
