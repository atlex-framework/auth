import type { NextFunction, Request, Response } from 'express'

import type { AuthConfig } from '../config/AuthConfig.js'
import type { SessionManager } from '../session/SessionManager.js'
import { parseCookies } from '../support/parseCookies.js'
import { serializeCookie } from '../support/serializeCookie.js'

function isUuid(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(s)
}

function isPromise(v: unknown): v is Promise<unknown> {
  return (
    typeof v === 'object' &&
    v !== null &&
    'then' in v &&
    typeof (v as Promise<unknown>).then === 'function'
  )
}

/**
 * Boots a {@link Session}, attaches it to `req.session`, persists it after the request.
 */
export class StartSession {
  private readonly sessionManager: SessionManager

  private readonly config: AuthConfig['session']

  /**
   * @param sessionManager - Session factory for the app.
   * @param config - Session config slice.
   */
  public constructor(sessionManager: SessionManager, config: AuthConfig['session']) {
    this.sessionManager = sessionManager
    this.config = config
  }

  /**
   * Express middleware entrypoint.
   */
  public async handle(req: Request, res: Response, next: NextFunction): Promise<void> {
    await this.sessionManager.openStore()
    this.sessionManager.primeCookieStore(req.headers.cookie)
    const session = this.sessionManager.session()
    const jar = parseCookies(req.headers.cookie)
    const rawId = jar[this.config.cookie]
    if (rawId !== undefined && rawId.length > 0 && isUuid(rawId)) {
      session.setId(rawId)
    }
    await session.start()
    session.ageFlashData()
    req.session = session

    const store = this.sessionManager.store()
    if (
      this.config.gcProbability > 0 &&
      Math.random() * this.config.gcDivisor < this.config.gcProbability
    ) {
      void store.gc(this.config.lifetime * 60).catch(() => undefined)
    }

    let err: unknown
    try {
      const out = next()
      if (isPromise(out)) {
        await out
      }
    } catch (e) {
      err = e
    }

    await session.save()
    const cookiePayload = this.sessionManager.cookieStorePayload()
    const value = cookiePayload ?? session.getId()
    if (!res.headersSent) {
      res.append(
        'Set-Cookie',
        serializeCookie(
          this.config.cookie,
          value,
          this.config,
          this.config.expireOnClose ? undefined : this.config.lifetime * 60,
        ),
      )
    }

    if (err !== undefined) {
      next(err)
    }
  }
}
