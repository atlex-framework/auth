import { AuthenticationError } from './AuthenticationError.js'

/**
 * Thrown when a JWT is syntactically valid but past its `exp` claim.
 */
export class TokenExpiredError extends AuthenticationError {
  /**
   * @param message - Human-readable reason.
   */
  public constructor(message = 'Token has expired') {
    super(message, 'E_TOKEN_EXPIRED')
    ;(this as unknown as { name: string }).name = 'TokenExpiredError'
  }
}
