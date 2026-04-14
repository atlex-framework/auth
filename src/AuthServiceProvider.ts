import type { Application, RequestHandler } from '@atlex/core'
import { Route, ServiceProvider } from '@atlex/core'
import type { QueryBuilder } from '@atlex/orm'
import type { NextFunction, Request, Response } from 'express'
import type { Redis } from 'ioredis'

import { AuthManager, type UserProviderFactory } from './AuthManager.js'
import { attachAuthorizesRequests } from './authorization/AuthorizesRequests.js'
import { Gate } from './authorization/Gate.js'
import type { Policy } from './authorization/Policy.js'
import type { AuthConfig } from './config/AuthConfig.js'
import type { AuthEventDispatcher } from './events/AuthEventDispatcher.js'
import { HashManager } from './hashing/HashManager.js'
import { JwtBlacklist } from './jwt/JwtBlacklist.js'
import { JwtProvider } from './jwt/JwtProvider.js'
import { MemoryBlacklistStore } from './jwt/MemoryBlacklistStore.js'
import { RedisBlacklistStore } from './jwt/RedisBlacklistStore.js'
import { RefreshTokenRepository } from './jwt/RefreshTokenRepository.js'
import { AuthMiddleware } from './middleware/AuthMiddleware.js'
import { EnsureEmailIsVerified } from './middleware/EnsureEmailIsVerified.js'
import { StartSession } from './middleware/StartSession.js'
import { ThrottleLogins } from './middleware/ThrottleLogins.js'
import { DatabaseTokenRepository } from './passwords/DatabaseTokenRepository.js'
import { PasswordBroker } from './passwords/PasswordBroker.js'
import { SessionManager } from './session/SessionManager.js'
import { MemoryRateLimiter } from './support/MemoryRateLimiter.js'
import { EmailVerifier } from './verification/EmailVerifier.js'

export interface AuthProviderBindings {
  /**
   * Fully merged auth configuration (defaults applied by caller if needed).
   */
  readonly config: AuthConfig

  /**
   * Builds user providers for configured `auth.providers` keys.
   */
  readonly userProviderFactory: UserProviderFactory

  /**
   * Optional Knex-backed query factory (sessions, password resets, refresh tokens).
   */
  readonly query?: () => QueryBuilder

  /**
   * Optional Redis client for JWT blacklist / session / refresh stores.
   */
  readonly redis?: Redis

  /**
   * Optional auth event sink (defaults to no-op).
   */
  readonly dispatch?: AuthEventDispatcher

  /**
   * Optional policy resolver (defaults to `new PolicyClass()`).
   */
  readonly resolvePolicy?: <T extends Policy>(PolicyClass: new (...args: never[]) => T) => T
}

/**
 * Registers `auth`, `gate`, `hash`, `session`, and related middleware aliases.
 */
export class AuthServiceProvider extends ServiceProvider {
  private readonly bindings: AuthProviderBindings

  /**
   * @param bindings - Runtime factories and merged configuration.
   */
  public constructor(bindings: AuthProviderBindings) {
    super()
    this.bindings = bindings
  }

  /**
   * @inheritdoc
   */
  public register(app: Application): void {
    const cfg = this.bindings.config
    const dispatch: AuthEventDispatcher = this.bindings.dispatch ?? (() => undefined)

    app.singleton('hash', () => new HashManager(cfg.hashing, cfg.defaults.hasher))

    app.singleton('jwt', () => new JwtProvider(cfg.jwt))

    const refreshRepo = new RefreshTokenRepository(
      this.bindings.query !== undefined
        ? {
            mode: 'database',
            table: 'refresh_tokens',
            query: this.bindings.query,
          }
        : { mode: 'memory' },
    )
    app.singleton('auth.refresh', () => refreshRepo)

    let jwtBlacklist: JwtBlacklist | null = null
    if (cfg.jwt.blacklist.enabled) {
      const grace = cfg.jwt.blacklist.gracePeriod
      if (cfg.jwt.blacklist.driver === 'redis') {
        const redis = this.bindings.redis
        if (redis === undefined) {
          throw new Error('AuthServiceProvider: redis blacklist requires bindings.redis.')
        }
        jwtBlacklist = new JwtBlacklist(new RedisBlacklistStore(redis, 'atlex_jwt_bl:'), grace)
      } else {
        jwtBlacklist = new JwtBlacklist(new MemoryBlacklistStore(), grace)
      }
    }
    app.container.instance('auth.blacklist', jwtBlacklist)

    const sessionManager = new SessionManager(cfg.session, {
      redis: this.bindings.redis,
      query: this.bindings.query,
    })
    app.singleton('session.manager', () => sessionManager)

    const passwordBrokers: Record<string, PasswordBroker> = {}
    if (this.bindings.query !== undefined) {
      const appKey = cfg.appKey ?? cfg.jwt.secret ?? ''
      for (const [name, slice] of Object.entries(cfg.passwords)) {
        const provider = this.bindings.userProviderFactory(slice.provider)
        const tokens = new DatabaseTokenRepository(
          this.bindings.query,
          slice.table,
          appKey,
          slice.expire,
          slice.throttle,
        )
        passwordBrokers[name] = new PasswordBroker(tokens, provider, slice, dispatch)
      }
    }

    app.singleton(
      'auth',
      () =>
        new AuthManager(
          cfg,
          app.make<HashManager>('hash'),
          app.make<JwtProvider>('jwt'),
          refreshRepo,
          jwtBlacklist,
          sessionManager,
          dispatch,
          this.bindings.userProviderFactory,
          passwordBrokers,
        ),
    )

    const resolvePolicy =
      this.bindings.resolvePolicy ??
      (<T extends Policy>(PolicyClass: new (...args: never[]) => T) => new PolicyClass())

    app.singleton(
      'gate',
      () =>
        new Gate(
          async () => await app.make<AuthManager>('auth').user(),
          (c) => resolvePolicy(c),
        ),
    )

    app.singleton(
      'auth.verifier',
      () =>
        new EmailVerifier(
          cfg.appKey ?? cfg.jwt.secret ?? '',
          cfg.verification.expire,
          cfg.jwt.appUrl ?? 'http://localhost:3000',
          dispatch,
        ),
    )

    app.singleton('auth.rateLimiter', () => new MemoryRateLimiter())
  }

  /**
   * @inheritdoc
   */
  public boot(app: Application): void {
    const cfg = this.bindings.config
    const sessionManager = app.make<SessionManager>('session.manager')
    const auth = app.make<AuthManager>('auth')
    const gate = app.make<Gate>('gate')
    const limiter = app.make<MemoryRateLimiter>('auth.rateLimiter')
    const dispatch: AuthEventDispatcher = this.bindings.dispatch ?? (() => undefined)

    const startSession = new StartSession(sessionManager, cfg.session)
    const authMiddleware = new AuthMiddleware(auth)
    const verified = new EnsureEmailIsVerified()
    const throttle = new ThrottleLogins(limiter, cfg.throttle, dispatch)

    const bindCtx: RequestHandler = (req: Request, _res: Response, next: NextFunction): void => {
      attachAuthorizesRequests(req, gate)
      next()
    }

    Route.middleware('auth.context', bindCtx)
    Route.middleware('auth.session', (req: Request, res: Response, next: NextFunction) => {
      void startSession.handle(req, res, next)
    })
    Route.middleware('auth', (req: Request, res: Response, next: NextFunction) => {
      void authMiddleware.handle()(req, res, next)
    })
    Route.middleware('verified', (req: Request, res: Response, next: NextFunction) => {
      void verified.handle(req, res, next)
    })
    Route.middleware('throttle.login', (req: Request, res: Response, next: NextFunction) => {
      void throttle.handle(req, res, next)
    })
  }
}
