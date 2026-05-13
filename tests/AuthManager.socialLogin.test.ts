import { describe, expect, it } from 'vitest'

import { AuthManager } from '../src/AuthManager.js'
import { defaultAuthConfig } from '../src/config/defaultAuthConfig.js'
import type { Authenticatable } from '../src/contracts/Authenticatable.js'
import type { UserProvider } from '../src/contracts/UserProvider.js'
import { HashManager } from '../src/hashing/HashManager.js'
import { JwtProvider } from '../src/jwt/JwtProvider.js'
import { RefreshTokenRepository } from '../src/jwt/RefreshTokenRepository.js'
import type { SocialProvider, SocialUser } from '../src/providers/SocialProvider.js'
import { SessionManager } from '../src/session/SessionManager.js'

class TestUser implements Authenticatable {
  public constructor(private readonly id: number) {}

  public getAuthIdentifierName(): string {
    return 'id'
  }

  public getAuthIdentifier(): number {
    return this.id
  }

  public getAuthPassword(): string {
    return 'unused'
  }

  public getRememberToken(): string | null {
    return null
  }

  public setRememberToken(_token: string): void {
    /* noop */
  }

  public getRememberTokenName(): string {
    return 'remember_token'
  }
}

describe('AuthManager.socialLogin', () => {
  it('verifies the social token, passes the social user to the resolver, and returns the user', async () => {
    const config = defaultAuthConfig()
    const manager = new AuthManager(
      config,
      new HashManager(config.hashing, config.defaults.hasher),
      new JwtProvider(config.jwt),
      new RefreshTokenRepository({ mode: 'memory' }),
      null,
      new SessionManager(config.session),
      () => undefined,
      (): UserProvider => {
        throw new Error('User provider should not be used by socialLogin.')
      },
      {},
    )
    const socialUser: SocialUser = {
      provider: 'google',
      providerId: 'google-user-1',
      email: 'parent@example.com',
      emailVerified: true,
      name: 'Parent User',
      avatarUrl: null,
      raw: { sub: 'google-user-1' },
    }
    const verifiedTokens: string[] = []
    const provider: SocialProvider = {
      async verify(token) {
        verifiedTokens.push(token)
        return socialUser
      },
    }
    const resolvedSocialUsers: SocialUser[] = []
    const user = new TestUser(42)

    const result = await manager.socialLogin(provider, 'id-token', async (verifiedSocialUser) => {
      resolvedSocialUsers.push(verifiedSocialUser)
      return user
    })

    expect(verifiedTokens).toEqual(['id-token'])
    expect(resolvedSocialUsers).toEqual([socialUser])
    expect(result).toBe(user)
  })
})
