import { AtlexError } from '@atlex/core'

import type { AuthorizationResponse } from '../authorization/AuthorizationResponse.js'

/**
 * Thrown when an authorization check fails.
 */
export class AuthorizationError extends AtlexError {
  /**
   * Suggested HTTP status for HTTP adapters.
   */
  public readonly status = 403

  /**
   * Optional structured policy response that produced this error.
   */
  public readonly policyResponse?: AuthorizationResponse

  /**
   * @param message - Human-readable reason.
   * @param policyResponse - Optional originating response object.
   */
  public constructor(message = 'Forbidden', policyResponse?: AuthorizationResponse) {
    super(message, 'E_AUTHORIZATION')
    ;(this as unknown as { name: string }).name = 'AuthorizationError'
    this.policyResponse = policyResponse
  }
}
