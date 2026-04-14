/**
 * Full authentication / session / JWT configuration surface for `@atlex/auth`.
 */
export interface AuthConfig {
  readonly defaults: {
    readonly guard: string
    readonly passwords: string
    readonly hasher: string
  }

  readonly guards: Record<
    string,
    {
      readonly driver: 'session' | 'token'
      readonly provider: string
    }
  >

  readonly providers: Record<
    string,
    {
      readonly driver: 'orm' | 'database'
      readonly model?: string
      readonly table?: string
    }
  >

  readonly passwords: Record<
    string,
    {
      readonly provider: string
      readonly table: string
      readonly expire: number
      readonly throttle: number
    }
  >

  readonly jwt: {
    readonly algorithm:
      | 'HS256'
      | 'HS384'
      | 'HS512'
      | 'RS256'
      | 'RS384'
      | 'RS512'
      | 'ES256'
      | 'ES384'
      | 'ES512'
    readonly secret?: string
    readonly keys?: { readonly public: string; readonly private: string }
    readonly accessTokenTtl: string
    readonly refreshTokenTtl: string
    readonly refreshTokenRotation: boolean
    readonly refreshTokenFamilyTracking: boolean
    readonly blacklist: {
      readonly enabled: boolean
      readonly driver: 'redis' | 'database' | 'memory'
      readonly gracePeriod: number
    }
    readonly issuer?: string
    readonly audience?: string
    readonly appUrl?: string
  }

  readonly session: {
    readonly driver: 'redis' | 'database' | 'cookie' | 'file' | 'null'
    readonly lifetime: number
    readonly expireOnClose: boolean
    readonly encrypt: boolean
    readonly cookie: string
    readonly path: string
    readonly domain: string | null
    readonly secure: boolean | 'auto'
    readonly httpOnly: boolean
    readonly sameSite: 'Lax' | 'Strict' | 'None'
    readonly gcProbability: number
    readonly gcDivisor: number
    readonly files: string
    readonly table: string
    readonly connection?: string
    readonly prefix: string
    readonly encryptionKey?: string
  }

  readonly hashing: {
    readonly bcrypt: { readonly rounds: number }
    readonly argon2: {
      readonly memory: number
      readonly threads: number
      readonly time: number
      readonly type: 'argon2i' | 'argon2d' | 'argon2id'
    }
    readonly scrypt: {
      readonly cost: number
      readonly blockSize: number
      readonly parallelization: number
    }
  }

  readonly verification: {
    readonly expire: number
  }

  readonly throttle: {
    readonly maxAttempts: number
    readonly decayMinutes: number
  }

  /**
   * Optional signing key for cookies and signed URLs (defaults to `jwt.secret` when omitted).
   */
  readonly appKey?: string
}
