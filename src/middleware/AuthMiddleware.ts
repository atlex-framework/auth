import type { NextFunction, Request, Response } from 'express'

import type { AuthManager } from '../AuthManager.js'
import { AuthenticationError } from '../errors/AuthenticationError.js'
import { TokenGuard } from '../guards/TokenGuard.js'

/**
 * Ensures at least one configured guard successfully authenticates the request.
 */
export class AuthMiddleware {
  private readonly auth: AuthManager

  /**
   * @param auth - Authentication manager.
   */
  public constructor(auth: AuthManager) {
    this.auth = auth
  }

  /**
   * Express middleware factory (`auth`, `auth:api`, ...).
   *
   * @param guards - Guard names to try in order; defaults to the configured default guard.
   */
  public handle(
    guards?: string[],
  ): (req: Request, res: Response, next: NextFunction) => Promise<void> {
    const list = guards !== undefined && guards.length > 0 ? guards : [undefined]
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      for (const name of list) {
        const g = this.auth.guard(name)
        if (await g.check()) {
          this.auth.shouldUse(name ?? this.auth.defaultGuardName())
          req.user = (await g.user()) ?? undefined
          next()
          return
        }
      }
      if (
        list.some((n) => {
          try {
            return this.auth.guard(n) instanceof TokenGuard
          } catch {
            return false
          }
        })
      ) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="api"')
      }
      next(new AuthenticationError())
    }
  }
}
