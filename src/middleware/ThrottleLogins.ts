import type { NextFunction, Request, Response } from 'express'

import type { AuthConfig } from '../config/AuthConfig.js'
import { LockoutError } from '../errors/LockoutError.js'
import type { AuthEventDispatcher } from '../events/AuthEventDispatcher.js'
import { Lockout } from '../events/Lockout.js'
import type { MemoryRateLimiter } from '../support/MemoryRateLimiter.js'

/**
 * Rate-limits login routes keyed by IP + email field.
 */
export class ThrottleLogins {
  private readonly limiter: MemoryRateLimiter

  private readonly config: AuthConfig['throttle']

  private readonly dispatch: AuthEventDispatcher

  private readonly emailField: string

  /**
   * @param limiter - Shared rate limiter instance.
   * @param config - Throttle slice from auth config.
   * @param dispatch - Event dispatcher.
   * @param emailField - Body/query field used for the throttle key.
   */
  public constructor(
    limiter: MemoryRateLimiter,
    config: AuthConfig['throttle'],
    dispatch: AuthEventDispatcher,
    emailField = 'email',
  ) {
    this.limiter = limiter
    this.config = config
    this.dispatch = dispatch
    this.emailField = emailField
  }

  /**
   * Express middleware entrypoint.
   */
  public async handle(req: Request, res: Response, next: NextFunction): Promise<void> {
    const ip = typeof req.ip === 'string' ? req.ip : 'unknown'
    const body = req.body as Record<string, unknown> | undefined
    const emailRaw = body?.[this.emailField]
    const email = typeof emailRaw === 'string' ? emailRaw : 'unknown'
    const key = `login|${ip}|${email}`
    if (this.limiter.tooManyAttempts(key, this.config.maxAttempts)) {
      const seconds = this.limiter.availableIn(key)
      void this.dispatch(new Lockout({ email, ip, seconds }))
      res.setHeader('Retry-After', String(seconds))
      next(new LockoutError(seconds))
      return
    }

    res.on('finish', () => {
      if (res.statusCode >= 400) {
        this.limiter.hit(key, this.config.decayMinutes * 60)
      } else {
        this.limiter.clear(key)
      }
    })

    next()
  }
}
