import { UnauthorizedHttpException } from '@atlex/core'

import type { GoogleSocialUser, SocialProvider } from './SocialProvider.js'

const DEFAULT_TOKEN_INFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo'

/**
 * Options for Google OAuth2 ID-token verification.
 */
export interface GoogleProviderOptions {
  /**
   * Expected Google OAuth client id for the token `aud` claim.
   */
  readonly clientId: string

  /**
   * Tokeninfo endpoint override, primarily for tests.
   */
  readonly tokenInfoEndpoint?: string

  /**
   * Fetch implementation override, primarily for tests.
   */
  readonly fetch?: typeof globalThis.fetch
}

/**
 * Verifies Google OAuth2 ID tokens and normalizes their tokeninfo payload.
 */
export class GoogleProvider implements SocialProvider<GoogleSocialUser> {
  private readonly clientId: string

  private readonly tokenInfoEndpoint: string

  private readonly fetch: typeof globalThis.fetch

  /**
   * @param options - Google provider verification options.
   */
  public constructor(options: GoogleProviderOptions) {
    this.clientId = options.clientId
    this.tokenInfoEndpoint = options.tokenInfoEndpoint ?? DEFAULT_TOKEN_INFO_ENDPOINT
    this.fetch = options.fetch ?? globalThis.fetch
  }

  /**
   * @param idToken - Google-issued ID token.
   * @returns Normalized Google social user profile.
   * @throws UnauthorizedHttpException When the token is missing, rejected, or malformed.
   */
  public async verify(idToken: string): Promise<GoogleSocialUser> {
    if (idToken.trim().length === 0) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Google ID token')
    }
    const response = await this.fetch(
      `${this.tokenInfoEndpoint}?id_token=${encodeURIComponent(idToken)}`,
    )
    if (!response.ok) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Google ID token')
    }
    const payload = await response.json()
    if (!isRecord(payload)) {
      throw new UnauthorizedHttpException(undefined, 'Invalid Google token payload')
    }
    return this.toSocialUser(payload)
  }

  private toSocialUser(payload: Record<string, unknown>): GoogleSocialUser {
    const audience = payload.aud
    if (typeof audience !== 'string' || audience !== this.clientId) {
      throw new UnauthorizedHttpException(undefined, 'Google token audience mismatch')
    }
    const subject = payload.sub
    const email = payload.email
    if (typeof subject !== 'string' || subject.length === 0 || typeof email !== 'string') {
      throw new UnauthorizedHttpException(undefined, 'Invalid Google token payload')
    }
    return {
      provider: 'google',
      providerId: subject,
      googleId: subject,
      email,
      emailVerified: payload.email_verified === true || payload.email_verified === 'true',
      name: typeof payload.name === 'string' ? payload.name : null,
      avatarUrl: typeof payload.picture === 'string' ? payload.picture : null,
      raw: payload,
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
