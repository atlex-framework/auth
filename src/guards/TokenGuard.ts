import type { Request } from 'express'

import type { AuthConfig } from '../config/AuthConfig.js'
import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { Guard } from '../contracts/Guard.js'
import type { UserProvider } from '../contracts/UserProvider.js'
import { InvalidTokenError } from '../errors/InvalidTokenError.js'
import { TokenBlacklistedError } from '../errors/TokenBlacklistedError.js'
import { TokenExpiredError } from '../errors/TokenExpiredError.js'
import { Attempting } from '../events/Attempting.js'
import { Authenticated } from '../events/Authenticated.js'
import type { AuthEventDispatcher } from '../events/AuthEventDispatcher.js'
import { Failed } from '../events/Failed.js'
import { Login } from '../events/Login.js'
import { Logout } from '../events/Logout.js'
import { type JwtBlacklist } from '../jwt/JwtBlacklist.js'
import type { JwtProvider } from '../jwt/JwtProvider.js'
import { RefreshTokenRepository } from '../jwt/RefreshTokenRepository.js'
import type { TokenAttemptResult } from '../jwt/TokenAttemptResult.js'
import type { TokenPair } from '../jwt/TokenPair.js'
import { parseCookies } from '../support/parseCookies.js'

function stripCredentials(credentials: Record<string, unknown>): Record<string, unknown> {
  const { password: _p, ...rest } = credentials
  return rest
}

/**
 * JWT (Bearer) authentication guard.
 */
export class TokenGuard implements Guard {
  private readonly jwt: JwtProvider

  private readonly provider: UserProvider

  private readonly request: Request

  private readonly blacklist: JwtBlacklist | null

  private readonly refreshRepo: RefreshTokenRepository

  private readonly config: AuthConfig['jwt']

  private readonly dispatch: AuthEventDispatcher

  private readonly guardName: string

  private cachedUser: Authenticatable | null | undefined

  /**
   * @param jwt - JWT signer/verifier.
   * @param provider - User lookup.
   * @param request - Current HTTP request.
   * @param blacklist - Optional blacklist when enabled in config.
   * @param refreshRepo - Refresh-token persistence.
   * @param config - JWT config slice.
   * @param dispatch - Event sink.
   * @param guardName - Registered guard key (for events).
   */
  public constructor(
    jwt: JwtProvider,
    provider: UserProvider,
    request: Request,
    blacklist: JwtBlacklist | null,
    refreshRepo: RefreshTokenRepository,
    config: AuthConfig['jwt'],
    dispatch: AuthEventDispatcher,
    guardName: string,
  ) {
    this.jwt = jwt
    this.provider = provider
    this.request = request
    this.blacklist = blacklist
    this.refreshRepo = refreshRepo
    this.config = config
    this.dispatch = dispatch
    this.guardName = guardName
  }

  /**
   * @inheritdoc
   */
  public async check(): Promise<boolean> {
    return (await this.user()) !== null
  }

  /**
   * @inheritdoc
   */
  public async guest(): Promise<boolean> {
    return !(await this.check())
  }

  /**
   * @inheritdoc
   */
  public async user(): Promise<Authenticatable | null> {
    if (this.cachedUser !== undefined) {
      return this.cachedUser
    }
    const token = this.getTokenFromRequest()
    if (token === null) {
      this.cachedUser = null
      return null
    }
    try {
      if (this.blacklist !== null && (await this.blacklist.isBlacklisted(token))) {
        throw new TokenBlacklistedError()
      }
      const payload = await this.jwt.verify(token)
      if (payload.typ !== undefined && payload.typ !== 'access') {
        throw new InvalidTokenError('Not an access token')
      }
      const user = await this.provider.retrieveById(payload.sub)
      if (user === null) {
        this.cachedUser = null
        return null
      }
      this.cachedUser = user
      void this.dispatch(new Authenticated({ guard: this.guardName, user }))
      return user
    } catch (err) {
      if (
        err instanceof TokenExpiredError ||
        err instanceof InvalidTokenError ||
        err instanceof TokenBlacklistedError
      ) {
        this.cachedUser = null
        return null
      }
      throw err
    }
  }

  /**
   * @inheritdoc
   */
  public async id(): Promise<string | number | null> {
    const u = await this.user()
    return u === null ? null : u.getAuthIdentifier()
  }

  /**
   * @inheritdoc
   */
  public async validate(credentials: Record<string, unknown>): Promise<boolean> {
    const user = await this.provider.retrieveByCredentials(credentials)
    if (user === null) {
      return false
    }
    return await this.provider.validateCredentials(user, credentials)
  }

  /**
   * @inheritdoc
   */
  public hasUser(): boolean {
    return this.cachedUser !== undefined && this.cachedUser !== null
  }

  /**
   * @inheritdoc
   */
  public setUser(user: Authenticatable): void {
    this.cachedUser = user
  }

  /**
   * Attempts credential login and returns JWT pair + user.
   *
   * @param credentials - Must include fields understood by the user provider (e.g. email/password).
   */
  public async attemptWithCredentials(
    credentials: Record<string, unknown>,
  ): Promise<TokenAttemptResult | null> {
    void this.dispatch(
      new Attempting({
        guard: this.guardName,
        credentials: stripCredentials(credentials),
        remember: false,
      }),
    )
    const user = await this.provider.retrieveByCredentials(credentials)
    if (user === null || !(await this.provider.validateCredentials(user, credentials))) {
      void this.dispatch(
        new Failed({
          guard: this.guardName,
          credentials: stripCredentials(credentials),
          ...(user !== null ? { user } : {}),
        }),
      )
      return null
    }
    void this.dispatch(new Login({ guard: this.guardName, user, remember: false }))
    const familyId = RefreshTokenRepository.newFamilyId()
    const accessToken = await this.jwt.generateAccessToken(user)
    const refreshToken = await this.jwt.generateRefreshToken(user, familyId)
    const decoded = await this.jwt.decode(refreshToken)
    const exp = typeof decoded.exp === 'number' ? new Date(decoded.exp * 1000) : new Date()
    const jti = decoded.jti
    await this.refreshRepo.create(user.getAuthIdentifier(), familyId, jti, exp)
    const pair = await this.buildPair(accessToken, refreshToken)
    return { ...pair, user }
  }

  /**
   * Rotates refresh token according to {@link AuthConfig.jwt} rotation settings.
   *
   * @param refreshToken - Previously issued refresh JWT.
   * @returns New token pair.
   */
  public async refresh(refreshToken: string): Promise<TokenPair> {
    let payload
    try {
      payload = await this.jwt.verify(refreshToken)
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        throw err
      }
      throw new InvalidTokenError()
    }
    if (payload.typ !== 'refresh') {
      throw new InvalidTokenError('Not a refresh token')
    }
    const jti = payload.jti
    const record = await this.refreshRepo.find(jti)
    if (record === null) {
      throw new InvalidTokenError('Unknown refresh token')
    }
    if (record.isRevoked) {
      if (this.config.refreshTokenFamilyTracking) {
        await this.refreshRepo.revokeFamily(record.familyId)
      }
      throw new InvalidTokenError('Refresh token reused or revoked')
    }
    const user = await this.provider.retrieveById(record.userId)
    if (user === null) {
      throw new InvalidTokenError('User no longer exists')
    }
    const accessToken = await this.jwt.generateAccessToken(user)
    if (!this.config.refreshTokenRotation) {
      return await this.buildPair(accessToken, refreshToken)
    }
    await this.refreshRepo.revoke(jti)
    const familyId = record.familyId
    const nextRefresh = await this.jwt.generateRefreshToken(user, familyId)
    const dec = await this.jwt.decode(nextRefresh)
    const exp = typeof dec.exp === 'number' ? new Date(dec.exp * 1000) : new Date()
    await this.refreshRepo.create(user.getAuthIdentifier(), familyId, dec.jti, exp)
    return await this.buildPair(accessToken, nextRefresh)
  }

  /**
   * Blacklists the current access token and revokes the refresh token when provided.
   */
  public async logout(): Promise<void> {
    const access = this.getTokenFromRequest()
    const user = await this.user()
    if (this.blacklist !== null && access !== null) {
      await this.blacklist.add(access)
    }
    const refresh = this.getRefreshFromRequest()
    if (refresh !== null) {
      try {
        const jti = this.jwt.getJti(refresh)
        await this.refreshRepo.revoke(jti)
      } catch {
        /* ignore malformed refresh on logout */
      }
    }
    void this.dispatch(new Logout({ guard: this.guardName, user }))
    this.cachedUser = undefined
  }

  /**
   * @returns Bearer token from header, `token` query param, or `token` cookie.
   */
  public getTokenFromRequest(): string | null {
    const authz = this.request.headers.authorization
    if (typeof authz === 'string' && authz.startsWith('Bearer ')) {
      const t = authz.slice(7).trim()
      return t.length > 0 ? t : null
    }
    const q = this.request.query.token
    if (typeof q === 'string' && q.length > 0) {
      return q
    }
    const cookies = parseCookies(this.request.headers.cookie)
    const c = cookies.token
    return c !== undefined && c.length > 0 ? c : null
  }

  private getRefreshFromRequest(): string | null {
    const body = this.request.body as Record<string, unknown> | undefined
    const fromBody =
      body !== undefined && typeof body.refreshToken === 'string' ? body.refreshToken : null
    if (fromBody !== null && fromBody.length > 0) {
      return fromBody
    }
    const h = this.request.headers['x-refresh-token']
    if (typeof h === 'string' && h.length > 0) {
      return h
    }
    return null
  }

  private async buildPair(accessToken: string, refreshToken: string): Promise<TokenPair> {
    const payload = await this.jwt.decode(accessToken)
    const expSec = payload.exp
    if (typeof expSec !== 'number') {
      throw new InvalidTokenError('Access token missing exp')
    }
    const expiresAt = new Date(expSec * 1000)
    const expiresIn = Math.max(0, expSec - Math.floor(Date.now() / 1000))
    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn,
      expiresAt,
    }
  }
}
