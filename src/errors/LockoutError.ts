import { AtlexError } from '@atlex/core'

/**
 * Thrown when login throttling rejects further attempts.
 */
export class LockoutError extends AtlexError {
  /**
   * Suggested HTTP status for HTTP adapters.
   */
  public readonly status = 429

  /**
   * Seconds until the client should retry.
   */
  public readonly retryAfter: number

  /**
   * @param retryAfter - Retry-After value in seconds.
   */
  public constructor(retryAfter: number) {
    super('Too many login attempts', 'E_LOCKOUT')
    ;(this as unknown as { name: string }).name = 'LockoutError'
    this.retryAfter = retryAfter
  }
}
