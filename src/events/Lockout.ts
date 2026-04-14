import { AtlexEvent } from '@atlex/core'

/**
 * Fired when login throttling rejects an attempt.
 */
export class Lockout extends AtlexEvent {
  /**
   * @param payload - Target email, client IP, and retry delay.
   */
  public constructor(
    public readonly payload: {
      readonly email: string
      readonly ip: string
      readonly seconds: number
    },
  ) {
    super()
  }
}
