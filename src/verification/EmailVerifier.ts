import { createHash, createHmac, timingSafeEqual } from 'node:crypto'

import type { Request } from 'express'

import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { MustVerifyEmail } from '../contracts/MustVerifyEmail.js'
import type { AuthEventDispatcher } from '../events/AuthEventDispatcher.js'
import { Verified } from '../events/Verified.js'

/**
 * Signed URL helpers for verifying email ownership.
 */
export class EmailVerifier {
  private readonly secret: string

  private readonly expireMinutes: number

  private readonly baseUrl: string

  private readonly dispatch: AuthEventDispatcher

  /**
   * @param secret - HMAC secret (typically `APP_KEY`).
   * @param expireMinutes - Signed link TTL.
   * @param baseUrl - Public application root URL.
   * @param dispatch - Event dispatcher.
   */
  public constructor(
    secret: string,
    expireMinutes: number,
    baseUrl: string,
    dispatch: AuthEventDispatcher,
  ) {
    this.secret = secret
    this.expireMinutes = expireMinutes
    this.baseUrl = baseUrl.replace(/\/$/, '')
    this.dispatch = dispatch
  }

  /**
   * Builds `/email/verify` with signed `id`, `hash`, and `expires` query parameters.
   */
  public async generateVerificationUrl(user: MustVerifyEmail): Promise<string> {
    const id = String((user as { id?: string | number }).id ?? '')
    const emailHash = createHash('sha256').update(user.getEmailForVerification()).digest('hex')
    const expires = Math.floor(Date.now() / 1000) + this.expireMinutes * 60
    const payload = `${id}|${emailHash}|${expires}`
    const sig = createHmac('sha256', this.secret).update(payload).digest('hex')
    const u = new URL(`${this.baseUrl}/email/verify`)
    u.searchParams.set('id', id)
    u.searchParams.set('hash', emailHash)
    u.searchParams.set('expires', String(expires))
    u.searchParams.set('signature', sig)
    return u.toString()
  }

  /**
   * Validates the signed URL on the incoming request and marks the user verified.
   */
  public async verify(
    request: Request,
    loadUser: (id: string) => Promise<(Authenticatable & MustVerifyEmail) | null>,
  ): Promise<boolean> {
    const q = request.query
    const id = typeof q.id === 'string' ? q.id : null
    const hash = typeof q.hash === 'string' ? q.hash : null
    const expiresRaw = typeof q.expires === 'string' ? q.expires : null
    const signature = typeof q.signature === 'string' ? q.signature : null
    if (id === null || hash === null || expiresRaw === null || signature === null) {
      return false
    }
    const expires = Number(expiresRaw)
    if (!Number.isFinite(expires) || expires < Math.floor(Date.now() / 1000)) {
      return false
    }
    const payload = `${id}|${hash}|${expires}`
    const expected = createHmac('sha256', this.secret).update(payload).digest('hex')
    const a = Buffer.from(expected, 'utf8')
    const b = Buffer.from(signature, 'utf8')
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return false
    }
    const user = await loadUser(id)
    if (user === null) {
      return false
    }
    const emailHash = createHash('sha256').update(user.getEmailForVerification()).digest('hex')
    if (emailHash !== hash) {
      return false
    }
    if (user.hasVerifiedEmail()) {
      return true
    }
    await user.markEmailAsVerified()
    void this.dispatch(new Verified({ user }))
    return true
  }
}
