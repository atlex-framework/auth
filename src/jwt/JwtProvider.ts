import { createSecretKey, randomUUID } from 'node:crypto'

import {
  decodeJwt,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
  type JWTPayload,
  type JWTVerifyOptions,
  type KeyLike,
} from 'jose'

import type { AuthConfig } from '../config/AuthConfig.js'
import type { Authenticatable } from '../contracts/Authenticatable.js'
import { InvalidTokenError } from '../errors/InvalidTokenError.js'
import { TokenExpiredError } from '../errors/TokenExpiredError.js'

import { parseDurationToSeconds } from './parseDuration.js'

export type AtlexJwtPayload = JWTPayload & {
  readonly sub: string
  readonly jti: string
  readonly typ?: string
  readonly fam?: string
}

/**
 * Signs and verifies JWT access/refresh tokens using `jose`.
 */
export class JwtProvider {
  private readonly config: AuthConfig['jwt']

  /**
   * @param config - JWT section of {@link AuthConfig}.
   */
  public constructor(config: AuthConfig['jwt']) {
    this.config = config
  }

  /**
   * @param payload - Claims to sign (iss/aud/iat/exp/jti applied automatically when missing).
   * @returns Compact-serialized JWT.
   */
  public async sign(payload: JWTPayload): Promise<string> {
    const jti =
      typeof payload.jti === 'string' && payload.jti.length > 0 ? payload.jti : randomUUID()
    const ttl = parseDurationToSeconds(this.config.accessTokenTtl)
    const now = Math.floor(Date.now() / 1000)
    const builder = new SignJWT({ ...payload, jti })
      .setProtectedHeader({ alg: this.config.algorithm })
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .setJti(jti)
    if (this.config.issuer !== undefined) {
      builder.setIssuer(this.config.issuer)
    }
    if (this.config.audience !== undefined) {
      builder.setAudience(this.config.audience)
    }
    const key = await this.getSigningKey()
    return await builder.sign(key)
  }

  /**
   * @param token - Compact JWT.
   * @returns Verified payload.
   * @throws TokenExpiredError When `exp` is in the past.
   * @throws InvalidTokenError On signature or claim mismatch.
   */
  public async verify(token: string): Promise<AtlexJwtPayload> {
    const options: JWTVerifyOptions = {
      algorithms: [this.config.algorithm],
    }
    if (this.config.issuer !== undefined) {
      options.issuer = this.config.issuer
    }
    if (this.config.audience !== undefined) {
      options.audience = this.config.audience
    }
    try {
      const key = await this.getVerificationKey()
      const { payload } = await jwtVerify(token, key, options)
      return this.assertPayload(payload)
    } catch (err) {
      if (err instanceof Error && err.name === 'JWTExpired') {
        throw new TokenExpiredError()
      }
      throw new InvalidTokenError()
    }
  }

  /**
   * Decodes a JWT without verifying the signature (introspection only).
   *
   * @param token - Compact JWT.
   * @returns Decoded payload.
   */
  public async decode(token: string): Promise<AtlexJwtPayload> {
    return this.assertPayload(decodeJwt(token))
  }

  /**
   * @param user - Authenticated principal.
   * @param claims - Optional extra claims.
   * @returns Signed access token.
   */
  public async generateAccessToken(
    user: Authenticatable,
    claims?: Record<string, unknown>,
  ): Promise<string> {
    const sub = String(user.getAuthIdentifier())
    return await this.sign({
      sub,
      typ: 'access',
      ...claims,
    })
  }

  /**
   * @param user - Authenticated principal.
   * @param familyId - Refresh token family identifier.
   * @returns Signed refresh token with extended TTL.
   */
  public async generateRefreshToken(user: Authenticatable, familyId?: string): Promise<string> {
    const sub = String(user.getAuthIdentifier())
    const jti = randomUUID()
    const ttl = parseDurationToSeconds(this.config.refreshTokenTtl)
    const now = Math.floor(Date.now() / 1000)
    const builder = new SignJWT({
      sub,
      typ: 'refresh',
      jti,
      ...(familyId !== undefined ? { fam: familyId } : {}),
    })
      .setProtectedHeader({ alg: this.config.algorithm })
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .setJti(jti)
    if (this.config.issuer !== undefined) {
      builder.setIssuer(this.config.issuer)
    }
    if (this.config.audience !== undefined) {
      builder.setAudience(this.config.audience)
    }
    const key = await this.getSigningKey()
    return await builder.sign(key)
  }

  /**
   * @param token - JWT string (may be expired).
   * @returns `jti` claim when present.
   */
  public getJti(token: string): string {
    const payload = decodeJwt(token)
    const jti = payload.jti
    if (typeof jti !== 'string' || jti.length === 0) {
      throw new InvalidTokenError('Token is missing jti')
    }
    return jti
  }

  private assertPayload(payload: JWTPayload): AtlexJwtPayload {
    const sub = payload.sub
    const jti = payload.jti
    if (typeof sub !== 'string' || sub.length === 0) {
      throw new InvalidTokenError('Token is missing sub')
    }
    if (typeof jti !== 'string' || jti.length === 0) {
      throw new InvalidTokenError('Token is missing jti')
    }
    return payload as AtlexJwtPayload
  }

  private async getSigningKey(): Promise<KeyLike> {
    const alg = this.config.algorithm
    if (alg.startsWith('HS')) {
      const secret = this.config.secret
      if (secret === undefined || secret.length === 0) {
        throw new Error('JwtProvider: HS* algorithms require auth.jwt.secret.')
      }
      return createSecretKey(new TextEncoder().encode(secret)) as KeyLike
    }
    const keys = this.config.keys
    if (keys === undefined) {
      throw new Error('JwtProvider: asymmetric algorithms require auth.jwt.keys.')
    }
    if (alg.startsWith('RS') || alg.startsWith('ES')) {
      return await importPKCS8(keys.private, alg)
    }
    throw new Error(`JwtProvider: unsupported algorithm ${alg}.`)
  }

  private async getVerificationKey(): Promise<KeyLike> {
    const alg = this.config.algorithm
    if (alg.startsWith('HS')) {
      const secret = this.config.secret
      if (secret === undefined || secret.length === 0) {
        throw new Error('JwtProvider: HS* algorithms require auth.jwt.secret.')
      }
      return createSecretKey(new TextEncoder().encode(secret)) as KeyLike
    }
    const keys = this.config.keys
    if (keys === undefined) {
      throw new Error('JwtProvider: asymmetric algorithms require auth.jwt.keys.')
    }
    if (alg.startsWith('RS') || alg.startsWith('ES')) {
      return await importSPKI(keys.public, alg)
    }
    throw new Error(`JwtProvider: unsupported algorithm ${alg}.`)
  }
}
