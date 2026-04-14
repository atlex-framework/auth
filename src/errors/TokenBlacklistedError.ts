import { AuthenticationError } from './AuthenticationError.js'

/**
 * Thrown when a JWT `jti` is present on the blacklist.
 */
export class TokenBlacklistedError extends AuthenticationError {
  /**
   * @param message - Human-readable reason.
   */
  public constructor(message = 'Token has been revoked') {
    super(message, 'E_TOKEN_BLACKLISTED')
    ;(this as unknown as { name: string }).name = 'TokenBlacklistedError'
  }
}
