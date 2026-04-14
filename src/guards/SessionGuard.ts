import { randomBytes } from 'node:crypto'

import type { Request, Response } from 'express'

import type { AuthConfig } from '../config/AuthConfig.js'
import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { StatefulGuard } from '../contracts/StatefulGuard.js'
import type { SupportsBasicAuth } from '../contracts/SupportsBasicAuth.js'
import type { UserProvider } from '../contracts/UserProvider.js'
import { AuthenticationError } from '../errors/AuthenticationError.js'
import { Attempting } from '../events/Attempting.js'
import { Authenticated } from '../events/Authenticated.js'
import type { AuthEventDispatcher } from '../events/AuthEventDispatcher.js'
import { CurrentDeviceLogout } from '../events/CurrentDeviceLogout.js'
import { Failed } from '../events/Failed.js'
import { Login } from '../events/Login.js'
import { Logout } from '../events/Logout.js'
import { OtherDeviceLogout } from '../events/OtherDeviceLogout.js'
import { type HashManager } from '../hashing/HashManager.js'
import { type Session } from '../session/Session.js'
import { parseCookies } from '../support/parseCookies.js'
import { packRememberCookie, unpackRememberCookie } from '../support/rememberCookie.js'
import { serializeCookie } from '../support/serializeCookie.js'

function stripCredentials(credentials: Record<string, unknown>): Record<string, unknown> {
  const { password: _p, ...rest } = credentials
  return rest
}

const REMEMBER_MAX_AGE = 60 * 60 * 24 * 365 * 5

/**
 * Cookie + server session authentication guard.
 */
export class SessionGuard implements StatefulGuard, SupportsBasicAuth {
  private readonly name: string

  private readonly provider: UserProvider

  private readonly session: Session

  private readonly request: Request

  private readonly response: Response

  private readonly hash: HashManager

  private readonly dispatch: AuthEventDispatcher

  private readonly sessionCfg: AuthConfig['session']

  private readonly appKey: string

  private readonly guardName: string

  private cachedUser: Authenticatable | null | undefined

  private rememberViaCookie = false

  /**
   * @param name - Logical guard name.
   * @param provider - User provider.
   * @param session - Request session instance.
   * @param request - HTTP request.
   * @param response - HTTP response (Set-Cookie).
   * @param hash - Password/token hasher.
   * @param dispatch - Event dispatcher.
   * @param sessionCfg - Session config slice.
   * @param appKey - Secret for remember-me signing.
   * @param guardName - Registered guard key for events.
   */
  public constructor(
    name: string,
    provider: UserProvider,
    session: Session,
    request: Request,
    response: Response,
    hash: HashManager,
    dispatch: AuthEventDispatcher,
    sessionCfg: AuthConfig['session'],
    appKey: string,
    guardName: string,
  ) {
    this.name = name
    this.provider = provider
    this.session = session
    this.request = request
    this.response = response
    this.hash = hash
    this.dispatch = dispatch
    this.sessionCfg = sessionCfg
    this.appKey = appKey
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
    this.rememberViaCookie = false
    const id = this.session.get<string | number | null>(this.sessionUserKey(), null)
    if (id !== null && id !== undefined && id !== '') {
      const user = await this.provider.retrieveById(id)
      if (user !== null) {
        this.cachedUser = user
        void this.dispatch(new Authenticated({ guard: this.guardName, user }))
        return user
      }
    }
    const fromRemember = await this.userFromRememberCookie()
    if (fromRemember !== null) {
      this.cachedUser = fromRemember
      this.rememberViaCookie = true
      void this.dispatch(new Authenticated({ guard: this.guardName, user: fromRemember }))
      return fromRemember
    }
    this.cachedUser = null
    return null
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
   * @inheritdoc
   */
  public async attempt(credentials: Record<string, unknown>, remember = false): Promise<boolean> {
    void this.dispatch(
      new Attempting({
        guard: this.guardName,
        credentials: stripCredentials(credentials),
        remember,
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
      return false
    }
    await this.login(user, remember)
    return true
  }

  /**
   * @inheritdoc
   */
  public async login(user: Authenticatable, remember = false): Promise<void> {
    await this.session.migrate(false)
    this.session.put(this.sessionUserKey(), user.getAuthIdentifier())
    if (remember) {
      const plain = randomBytes(20).toString('hex')
      const hashed = await this.hash.make(plain)
      await this.provider.updateRememberToken(user, hashed)
      const packed = packRememberCookie(user.getAuthIdentifier(), plain, this.appKey)
      this.response.append(
        'Set-Cookie',
        serializeCookie(this.rememberCookieName(), packed, this.sessionCfg, REMEMBER_MAX_AGE),
      )
    }
    this.cachedUser = user
    void this.dispatch(new Login({ guard: this.guardName, user, remember }))
  }

  /**
   * @inheritdoc
   */
  public async loginUsingId(
    id: string | number,
    remember = false,
  ): Promise<Authenticatable | false> {
    const user = await this.provider.retrieveById(id)
    if (user === null) {
      return false
    }
    await this.login(user, remember)
    return user
  }

  /**
   * @inheritdoc
   */
  public async logout(): Promise<void> {
    const user = await this.user()
    if (user !== null) {
      await this.provider.updateRememberToken(
        user,
        await this.hash.make(randomBytes(10).toString('hex')),
      )
    }
    this.response.append(
      'Set-Cookie',
      serializeCookie(this.rememberCookieName(), '', this.sessionCfg, 0),
    )
    await this.session.invalidate()
    this.cachedUser = undefined
    if (user !== null) {
      void this.dispatch(new CurrentDeviceLogout({ guard: this.guardName, user }))
    }
    void this.dispatch(new Logout({ guard: this.guardName, user }))
  }

  /**
   * Validates the password and rotates the persisted remember token, invalidating other devices' remember cookies.
   *
   * @param password - Current password confirmation.
   */
  public async logoutOtherDevices(password: string): Promise<void> {
    const user = await this.user()
    if (user === null) {
      throw new AuthenticationError('Not authenticated')
    }
    if (!(await this.provider.validateCredentials(user, { password }))) {
      throw new AuthenticationError('Invalid password')
    }
    const plain = randomBytes(20).toString('hex')
    const hashed = await this.hash.make(plain)
    await this.provider.updateRememberToken(user, hashed)
    this.response.append(
      'Set-Cookie',
      serializeCookie(this.rememberCookieName(), '', this.sessionCfg, 0),
    )
    void this.dispatch(new OtherDeviceLogout({ guard: this.guardName, user }))
  }

  /**
   * @inheritdoc
   */
  public viaRemember(): boolean {
    return this.rememberViaCookie
  }

  /**
   * @inheritdoc
   */
  public async basic(field = 'email', extra?: Record<string, unknown>): Promise<void> {
    const creds = this.parseBasicCredentials()
    if (creds === null) {
      this.challengeBasic()
      return
    }
    const ok = await this.attempt({ [field]: creds.user, password: creds.pass, ...extra }, false)
    if (!ok) {
      this.challengeBasic()
    }
  }

  /**
   * @inheritdoc
   */
  public async onceBasic(field = 'email', extra?: Record<string, unknown>): Promise<void> {
    const creds = this.parseBasicCredentials()
    if (creds === null) {
      this.challengeBasic()
      return
    }
    const user = await this.provider.retrieveByCredentials({
      [field]: creds.user,
      password: creds.pass,
      ...extra,
    })
    if (
      user === null ||
      !(await this.provider.validateCredentials(user, {
        [field]: creds.user,
        password: creds.pass,
        ...extra,
      }))
    ) {
      this.challengeBasic()
      return
    }
    this.setUser(user)
  }

  private sessionUserKey(): string {
    return `login_${this.name}_id`
  }

  private rememberCookieName(): string {
    return `remember_${this.name}`
  }

  private async userFromRememberCookie(): Promise<Authenticatable | null> {
    const jar = parseCookies(this.request.headers.cookie)
    const raw = jar[this.rememberCookieName()]
    if (raw === undefined || raw.length === 0) {
      return null
    }
    const unpacked = unpackRememberCookie(raw, this.appKey)
    if (unpacked === null) {
      return null
    }
    return await this.provider.retrieveByToken(unpacked.userId, unpacked.plainToken)
  }

  private parseBasicCredentials(): { user: string; pass: string } | null {
    const header = this.request.headers.authorization
    if (typeof header !== 'string' || !header.startsWith('Basic ')) {
      return null
    }
    let decoded: string
    try {
      decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8')
    } catch {
      return null
    }
    const idx = decoded.indexOf(':')
    if (idx <= 0) {
      return null
    }
    return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) }
  }

  private challengeBasic(): void {
    this.response.status(401)
    this.response.setHeader('WWW-Authenticate', 'Basic realm="atlex"')
    throw new AuthenticationError('Basic authentication required')
  }
}
