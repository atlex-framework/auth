import { AtlexError } from '@atlex/core'

/**
 * Thrown when authentication is required but missing or invalid.
 */
export class AuthenticationError extends AtlexError {
  /**
   * Suggested HTTP status for HTTP adapters.
   */
  public readonly status = 401

  /**
   * @param message - Human-readable reason.
   * @param code - Machine-readable code (defaults to `E_AUTHENTICATION`).
   */
  public constructor(message = 'Unauthenticated', code = 'E_AUTHENTICATION') {
    super(message, code)
    ;(this as unknown as { name: string }).name = 'AuthenticationError'
  }
}
