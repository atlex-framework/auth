import type { AuthConfig } from './AuthConfig.js'

/**
 * @returns Sane local-development defaults; override per environment in app config.
 */
export function defaultAuthConfig(): AuthConfig {
  const secret =
    process.env.APP_KEY ?? process.env.JWT_SECRET ?? 'change-me-in-production-min-32-chars!!'
  return {
    defaults: {
      guard: 'web',
      passwords: 'users',
      hasher: 'bcrypt',
    },
    guards: {
      web: { driver: 'session', provider: 'users' },
      api: { driver: 'token', provider: 'users' },
    },
    providers: {
      users: { driver: 'database', table: 'users' },
    },
    passwords: {
      users: {
        provider: 'users',
        table: 'password_resets',
        expire: 60,
        throttle: 60,
      },
    },
    jwt: {
      algorithm: 'HS256',
      secret,
      accessTokenTtl: '15m',
      refreshTokenTtl: '7d',
      refreshTokenRotation: true,
      refreshTokenFamilyTracking: true,
      blacklist: {
        enabled: false,
        driver: 'memory',
        gracePeriod: 0,
      },
      appUrl: process.env.APP_URL ?? 'http://localhost:3000',
    },
    session: {
      driver: 'null',
      lifetime: 120,
      expireOnClose: false,
      encrypt: false,
      cookie: 'atlex_session',
      path: '/',
      domain: null,
      secure: 'auto',
      httpOnly: true,
      sameSite: 'Lax',
      gcProbability: 2,
      gcDivisor: 100,
      files: './storage/sessions',
      table: 'sessions',
      prefix: 'atlex_session:',
      encryptionKey: secret,
    },
    hashing: {
      bcrypt: { rounds: 12 },
      argon2: { memory: 65536, threads: 1, time: 3, type: 'argon2id' },
      scrypt: { cost: 16384, blockSize: 8, parallelization: 1 },
    },
    verification: {
      expire: 60,
    },
    throttle: {
      maxAttempts: 5,
      decayMinutes: 1,
    },
    appKey: secret,
  }
}
