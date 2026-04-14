import type { NextFunction, Request, Response } from 'express'

import type { MustVerifyEmail } from '../contracts/MustVerifyEmail.js'
import { AuthorizationError } from '../errors/AuthorizationError.js'

function isMustVerifyEmail(u: unknown): u is MustVerifyEmail {
  return (
    typeof u === 'object' &&
    u !== null &&
    typeof (u as MustVerifyEmail).hasVerifiedEmail === 'function'
  )
}

/**
 * Rejects requests for users who must verify email but have not.
 */
export class EnsureEmailIsVerified {
  /**
   * Express middleware entrypoint.
   */
  public async handle(req: Request, _res: Response, next: NextFunction): Promise<void> {
    const u = req.user
    if (u === undefined || !isMustVerifyEmail(u)) {
      next()
      return
    }
    if (!u.hasVerifiedEmail()) {
      next(new AuthorizationError('Your email address is not verified.'))
      return
    }
    next()
  }
}
