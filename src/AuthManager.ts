import { getHttpContext } from '@atlex/core'
import type { Request, Response } from 'express'

import type { AuthConfig } from './config/AuthConfig.js'
import type { Authenticatable } from './contracts/Authenticatable.js'
import type { Guard } from './contracts/Guard.js'
import type { StatefulGuard } from './contracts/StatefulGuard.js'
import type { UserProvider } from './contracts/UserProvider.js'
import type { AuthEventDispatcher } from './events/AuthEventDispatcher.js'
import { SessionGuard } from './guards/SessionGuard.js'
import { TokenGuard } from './guards/TokenGuard.js'
import type { HashManager } from './hashing/HashManager.js'
import type { JwtBlacklist } from './jwt/JwtBlacklist.js'
import type { JwtProvider } from './jwt/JwtProvider.js'
import type { RefreshTokenRepository } from './jwt/RefreshTokenRepository.js'
import type { TokenAttemptResult } from './jwt/TokenAttemptResult.js'
import type { TokenPair } from './jwt/TokenPair.js'
import type { PasswordBroker } from './passwords/PasswordBroker.js'
import { PasswordBrokerManager } from './passwords/PasswordBrokerManager.js'
import type { SessionManager } from './session/SessionManager.js'

export type GuardFactory = (
  guardName: string,
  cfg: AuthConfig,
  req: Request,
) => Guard | StatefulGuard

export type UserProviderFactory = (providerName: string) => UserProvider

/**
 * Multi-guard authentication facade (session + JWT).
 */
export class AuthManager {
  private readonly config: AuthConfig

  private readonly hash: HashManager

  private readonly jwt: JwtProvider

  private readonly refreshRepo: RefreshTokenRepository

  private readonly jwtBlacklist: JwtBlacklist | null

  private readonly dispatch: AuthEventDispatcher

  private readonly baseUserProviderFactory: UserProviderFactory

  private readonly userProviderOverrides = new Map<string, UserProviderFactory>()

  private readonly guardCache = new WeakMap<Request, Map<string, Guard | StatefulGuard>>()

  private readonly extended = new Map<string, GuardFactory>()

  private readonly brokerManager: PasswordBrokerManager

  /**
   * @param config - Merged auth configuration.
   * @param hash - Hash manager.
   * @param jwt - JWT provider.
   * @param refreshRepo - Refresh-token repository.
   * @param jwtBlacklist - Optional blacklist facade.
   * @param sessionManager - Session factory.
   * @param dispatch - Auth event dispatcher.
   * @param userProviderFactory - Builds {@link UserProvider} instances by configured provider name.
   * @param passwordBrokers - Named password brokers (reset flows).
   */
  public constructor(
    config: AuthConfig,
    hash: HashManager,
    jwt: JwtProvider,
    refreshRepo: RefreshTokenRepository,
    jwtBlacklist: JwtBlacklist | null,
    sessionManager: SessionManager,
    dispatch: AuthEventDispatcher,
    userProviderFactory: UserProviderFactory,
    passwordBrokers: Record<string, PasswordBroker>,
  ) {
    this.config = config
    this.hash = hash
    this.jwt = jwt
    this.refreshRepo = refreshRepo
    this.jwtBlacklist = jwtBlacklist
    void sessionManager
    this.dispatch = dispatch
    this.baseUserProviderFactory = userProviderFactory
    this.brokerManager = new PasswordBrokerManager(passwordBrokers)
  }

  /**
   * Resolves a guard, caching per HTTP request.
   *
   * @param name - Guard key; defaults to `auth.defaults.guard`.
   */
  public guard(name?: string): Guard | StatefulGuard {
    const ctx = getHttpContext()
    const req = ctx.req
    const guardName = name ?? this.config.defaults.guard
    let map = this.guardCache.get(req)
    if (map === undefined) {
      map = new Map()
      this.guardCache.set(req, map)
    }
    const hit = map.get(guardName)
    if (hit !== undefined) {
      return hit
    }
    const built = this.resolveGuard(guardName, req, ctx.res)
    map.set(guardName, built)
    return built
  }

  /**
   * Marks which guard authenticated the current request (used by middleware).
   *
   * @param name - Guard key.
   */
  public shouldUse(name: string): void {
    getHttpContext().req.atlexAuthGuard = name
  }

  /**
   * Attempts login on the default guard (session boolean, JWT returns a token bundle + user).
   */
  public async attempt(
    credentials: Record<string, unknown>,
    remember?: boolean,
  ): Promise<boolean | TokenAttemptResult | null> {
    const g = this.guard()
    if (g instanceof TokenGuard) {
      return await g.attemptWithCredentials(credentials)
    }
    return await (g as SessionGuard).attempt(credentials, remember)
  }

  /**
   * Runs a credential check against the preferred token guard (`api` or first `token` driver).
   */
  public async attemptWithTokens(
    credentials: Record<string, unknown>,
  ): Promise<TokenAttemptResult | null> {
    const g = this.guard(this.resolveTokenGuardName())
    if (!(g instanceof TokenGuard)) {
      throw new Error('AuthManager.attemptWithTokens requires a token guard.')
    }
    return await g.attemptWithCredentials(credentials)
  }

  /**
   * @inheritdoc StatefulGuard.login
   */
  public async login(user: Authenticatable, remember?: boolean): Promise<void> {
    await (this.guard() as SessionGuard).login(user, remember)
  }

  /**
   * @inheritdoc StatefulGuard.loginUsingId
   */
  public async loginUsingId(
    id: string | number,
    remember?: boolean,
  ): Promise<Authenticatable | false> {
    return await (this.guard() as SessionGuard).loginUsingId(id, remember)
  }

  /**
   * @inheritdoc StatefulGuard.logout
   */
  public async logout(): Promise<void> {
    const g = this.guard()
    if (g instanceof TokenGuard) {
      await g.logout()
      return
    }
    await (g as SessionGuard).logout()
  }

  /**
   * @inheritdoc Guard.user
   */
  public async user(): Promise<Authenticatable | null> {
    return await this.guard().user()
  }

  /**
   * @inheritdoc Guard.id
   */
  public async id(): Promise<string | number | null> {
    return await this.guard().id()
  }

  /**
   * @inheritdoc Guard.check
   */
  public async check(): Promise<boolean> {
    return await this.guard().check()
  }

  /**
   * @inheritdoc Guard.guest
   */
  public async guest(): Promise<boolean> {
    return await this.guard().guest()
  }

  /**
   * @inheritdoc Guard.hasUser
   */
  public hasUser(): boolean {
    return this.guard().hasUser()
  }

  /**
   * @inheritdoc Guard.setUser
   */
  public setUser(user: Authenticatable): void {
    this.guard().setUser(user)
  }

  /**
   * @inheritdoc SessionGuard.viaRemember when session guard is default.
   */
  public viaRemember(): boolean {
    const g = this.guard()
    return g instanceof SessionGuard ? g.viaRemember() : false
  }

  /**
   * Refreshes JWTs using the default token guard.
   */
  public async refresh(refreshToken: string): Promise<TokenPair> {
    const g = this.guard(this.resolveTokenGuardName())
    if (!(g instanceof TokenGuard)) {
      throw new Error('AuthManager.refresh requires a token guard.')
    }
    return await g.refresh(refreshToken)
  }

  /**
   * Blacklists a JWT by opaque token string when enabled.
   */
  public async invalidateToken(token: string): Promise<void> {
    if (this.jwtBlacklist === null) {
      return
    }
    await this.jwtBlacklist.add(token)
  }

  /**
   * @param name - Password broker key.
   */
  public broker(name?: string): PasswordBroker {
    return this.brokerManager.broker(name ?? this.config.defaults.passwords)
  }

  /**
   * @param provider - Provider key from `auth.providers`.
   */
  public createUserProvider(provider?: string): UserProvider {
    const providerKeys = Object.keys(this.config.providers)
    const firstKey = providerKeys[0]
    const key = provider ?? (firstKey !== undefined ? firstKey : 'users')
    const override = this.userProviderOverrides.get(key)
    if (override !== undefined) {
      return override(key)
    }
    return this.baseUserProviderFactory(key)
  }

  /**
   * Registers a custom guard driver.
   */
  public extend(driver: string, factory: GuardFactory): void {
    this.extended.set(driver, factory)
  }

  /**
   * Overrides user provider factory registration (advanced).
   */
  public provider(name: string, factory: UserProviderFactory): void {
    this.userProviderOverrides.set(name, factory)
  }

  /**
   * Clears per-request guard caches (tests).
   */
  public forgetGuards(): void {
    this.guardCache.delete(getHttpContext().req)
  }

  /**
   * @returns Configured default guard key (`auth.defaults.guard`).
   */
  public defaultGuardName(): string {
    return this.config.defaults.guard
  }

  private resolveTokenGuardName(): string {
    if (this.config.guards.api?.driver === 'token') {
      return 'api'
    }
    const entry = Object.entries(this.config.guards).find(([, v]) => v.driver === 'token')
    if (entry === undefined) {
      throw new Error('AuthManager: no token guard is configured.')
    }
    return entry[0]
  }

  private resolveGuard(guardName: string, req: Request, res: Response): Guard | StatefulGuard {
    const cfg = this.config.guards[guardName]
    if (cfg === undefined) {
      throw new Error(`AuthManager: unknown guard "${guardName}".`)
    }
    const extended = this.extended.get(cfg.driver)
    if (extended !== undefined) {
      return extended(guardName, this.config, req)
    }
    const userProvider = this.createUserProvider(cfg.provider)
    if (cfg.driver === 'token') {
      return new TokenGuard(
        this.jwt,
        userProvider,
        req,
        this.jwtBlacklist,
        this.refreshRepo,
        this.config.jwt,
        this.dispatch,
        guardName,
      )
    }
    if (cfg.driver === 'session') {
      const session = req.session
      if (session === undefined) {
        throw new Error('SessionGuard requires StartSession middleware (req.session missing).')
      }
      const appKey = this.config.appKey ?? this.config.jwt.secret ?? ''
      return new SessionGuard(
        guardName,
        userProvider,
        session,
        req,
        res,
        this.hash,
        this.dispatch,
        this.config.session,
        appKey,
        guardName,
      )
    }
    throw new Error(`AuthManager: unsupported guard driver "${cfg.driver}".`)
  }
}
