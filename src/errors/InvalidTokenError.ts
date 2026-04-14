import { AuthenticationError } from './AuthenticationError.js'

/**
 * Thrown when a JWT fails signature or structural validation.
 */
export class InvalidTokenError extends AuthenticationError {
  /**
   * @param message - Human-readable reason.
   */
  public constructor(message = 'Invalid token') {
    super(message, 'E_INVALID_TOKEN')
    ;(this as unknown as { name: string }).name = 'InvalidTokenError'
  }
}
