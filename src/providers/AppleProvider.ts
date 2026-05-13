import { UnauthorizedHttpException } from '@atlex/core'
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import type { JWK } from 'jose'

import type { AppleSocialUser, SocialProvider } from './SocialProvider.js'

const DEFAULT_JWKS_ENDPOINT = 'https://appleid.apple.com/auth/keys'
const DEFAULT_JWKS_CACHE_TTL_MS = 60 * 60 * 1000
const APPLE_ISSUER = 'https://appleid.apple.com'

interface ApplePublicJwk extends JWK {
  readonly kid: string
}

interface JwksCache {
  readonly expiresAt: number
  readonly keys: readonly ApplePublicJwk[]
}

/**
 * Options for Apple identity-token verification.
 */
export interface AppleProviderOptions {
  /**
   * Expected Apple services ID or bundle ID for the token `aud` claim.
   */
  readonly clientId: string

  /**
   * Apple JWKS endpoint override, primarily for tests.
   */
  readonly jwksEndpoint?: string

  /**
   * Milliseconds to cache the fetched JWKS payload.
   */
  readonly jwksCacheTtlMs?: number

  /**
   * Fetch implementation override, primarily for tests.
   */
  readonly fetch?: typeof globalThis.fetch

  /**
   * Clock override used for deterministic cache tests.
   */
  readonly now?: () => number
}

/**
 * Apple first-sign-in user name parts.
 */
export interface AppleUserName {
  /**
   * User's given name from Apple's first sign-in profile payload.
   */
  readonly firstName?: string

  /**
   * User's family name from Apple's first sign-in profile payload.
   */
  readonly lastName?: string
}

/**
 * Optional Apple first-sign-in profile payload supplied by the client application.
 */
export interface AppleUserProfile {
  /**
   * Name supplied by Apple only on the user's first sign-in.
   */
  readonly name?: string | AppleUserName | null
}

/**
 * Verifies Sign in with Apple identity tokens against Apple's JWKS endpoint.
 */
export class AppleProvider implements SocialProvider<AppleSocialUser> {
  private readonly clientId: string

  private readonly jwksEndpoint: string

  private readonly jwksCacheTtlMs: number

  private readonly fetch: typeof globalThis.fetch

  private readonly now: () => number

  private jwksCache: JwksCache | null = null

  /**
   * @param options - Apple provider verification options.
   */
  public constructor(options: AppleProviderOptions) {
    this.clientId = options.clientId
    this.jwksEndpoint = options.jwksEndpoint ?? DEFAULT_JWKS_ENDPOINT
    this.jwksCacheTtlMs = options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS
    this.fetch = options.fetch ?? globalThis.fetch
    this.now = options.now ?? Date.now
  }

  /**
   * @param identityToken - Apple-issued identity token.
   * @param profile - Optional first-sign-in profile payload supplied by the client.
   * @returns Normalized Apple social user profile.
   * @throws UnauthorizedHttpException When the token is missing, rejected, or malformed.
   */
  public async verify(identityToken: string, profile?: AppleUserProfile): Promise<AppleSocialUser> {
    if (identityToken.trim().length === 0) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
    }

    const header = decodeAppleTokenHeader(identityToken)
    let jwk = await this.findJwk(header.kid)
    if (jwk === null) {
      this.jwksCache = null
      jwk = await this.findJwk(header.kid, true)
    }
    if (jwk === null) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
    }

    let payload: Record<string, unknown>
    try {
      const key = await importJWK(jwk, 'RS256')
      const result = await jwtVerify(identityToken, key, {
        algorithms: ['RS256'],
        audience: this.clientId,
        issuer: APPLE_ISSUER,
      })
      payload = { ...result.payload }
    } catch {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
    }
    return this.toSocialUser(payload, profile)
  }

  private async findJwk(kid: string, forceRefresh = false): Promise<ApplePublicJwk | null> {
    const keys = await this.getJwks(forceRefresh)
    return keys.find((key) => key.kid === kid) ?? null
  }

  private async getJwks(forceRefresh: boolean): Promise<readonly ApplePublicJwk[]> {
    const cached = this.jwksCache
    if (!forceRefresh && cached !== null && cached.expiresAt > this.now()) {
      return cached.keys
    }

    const response = await this.fetch(this.jwksEndpoint)
    if (!response.ok) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
    }
    const payload: unknown = await response.json()
    const keys = parseJwks(payload)
    this.jwksCache = {
      expiresAt: this.now() + this.jwksCacheTtlMs,
      keys,
    }
    return keys
  }

  private toSocialUser(
    payload: Record<string, unknown>,
    profile: AppleUserProfile | undefined,
  ): AppleSocialUser {
    const subject = payload.sub
    const email = payload.email
    if (typeof subject !== 'string' || subject.length === 0 || typeof email !== 'string') {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple token payload')
    }

    return {
      provider: 'apple',
      providerId: subject,
      appleId: subject,
      email,
      emailVerified: toBoolean(payload.email_verified),
      name: normalizeName(profile?.name),
      avatarUrl: null,
      isPrivateEmail: toBoolean(payload.is_private_email),
      raw: payload,
    }
  }
}

function decodeAppleTokenHeader(identityToken: string): { readonly kid: string } {
  try {
    const header = decodeProtectedHeader(identityToken)
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
      throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
    }
    return { kid: header.kid }
  } catch (error) {
    if (error instanceof UnauthorizedHttpException) {
      throw error
    }
    throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
  }
}

function parseJwks(payload: unknown): readonly ApplePublicJwk[] {
  if (!isRecord(payload) || !Array.isArray(payload.keys)) {
    throw new UnauthorizedHttpException(undefined, 'Invalid Apple identity token')
  }
  return payload.keys.filter(isApplePublicJwk)
}

function isApplePublicJwk(value: unknown): value is ApplePublicJwk {
  return isRecord(value) && typeof value.kid === 'string'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function toBoolean(value: unknown): boolean {
  return value === true || value === 'true'
}

function normalizeName(name: AppleUserProfile['name']): string | null {
  if (typeof name === 'string' && name.length > 0) {
    return name
  }
  if (!isRecord(name)) {
    return null
  }
  const parts = [name.firstName, name.lastName].filter(
    (part): part is string => typeof part === 'string' && part.length > 0,
  )
  return parts.length > 0 ? parts.join(' ') : null
}
