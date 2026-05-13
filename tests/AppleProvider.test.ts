import { UnauthorizedHttpException } from '@atlex/core'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { JWK, KeyLike } from 'jose'
import { describe, expect, it } from 'vitest'

import { AppleProvider } from '../src/providers/AppleProvider.js'

const CLIENT_ID = 'com.example.app'
const ISSUER = 'https://appleid.apple.com'
const JWKS_ENDPOINT = 'https://apple.test/auth/keys'

interface AppleTokenFixture {
  readonly identityToken: string
  readonly publicJwk: JWK
}

describe('AppleProvider', () => {
  it('fetches JWKS once, verifies an RS256 identity token, and returns an Apple social user', async () => {
    const fixture = await createAppleToken({
      sub: 'apple-user-1',
      email: 'parent@example.com',
      email_verified: 'true',
      is_private_email: 'false',
    })
    const { provider, calls } = createProvider(fixture.publicJwk)

    const user = await provider.verify(fixture.identityToken)

    expect(calls).toEqual([JWKS_ENDPOINT])
    expect(user).toMatchObject({
      provider: 'apple',
      providerId: 'apple-user-1',
      appleId: 'apple-user-1',
      email: 'parent@example.com',
      emailVerified: true,
      name: null,
      avatarUrl: null,
      isPrivateEmail: false,
    })
    expect(user.raw).toMatchObject({
      sub: 'apple-user-1',
      email: 'parent@example.com',
    })
  })

  it('caches JWKS for 1 hour and does not fetch again while the cache is fresh', async () => {
    const fixture = await createAppleToken({
      sub: 'apple-user-1',
      email: 'parent@example.com',
    })
    const { provider, calls } = createProvider(fixture.publicJwk, { now: () => 1_000 })

    await provider.verify(fixture.identityToken)
    await provider.verify(fixture.identityToken)

    expect(calls).toEqual([JWKS_ENDPOINT])
  })

  it('refetches JWKS after the 1-hour cache TTL expires', async () => {
    let now = 1_000
    const fixture = await createAppleToken({
      sub: 'apple-user-1',
      email: 'parent@example.com',
    })
    const { provider, calls } = createProvider(fixture.publicJwk, { now: () => now })

    await provider.verify(fixture.identityToken)
    now += 60 * 60 * 1000 + 1
    await provider.verify(fixture.identityToken)

    expect(calls).toEqual([JWKS_ENDPOINT, JWKS_ENDPOINT])
  })

  it('validates the issuer claim as Apple', async () => {
    const fixture = await createAppleToken(
      {
        sub: 'apple-user-1',
        email: 'parent@example.com',
      },
      { issuer: 'https://attacker.example.com' },
    )
    const { provider } = createProvider(fixture.publicJwk)

    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(
      'Invalid Apple identity token',
    )
  })

  it('validates the audience claim against the configured client id', async () => {
    const fixture = await createAppleToken(
      {
        sub: 'apple-user-1',
        email: 'parent@example.com',
      },
      { audience: 'com.other.app' },
    )
    const { provider } = createProvider(fixture.publicJwk)

    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(
      'Invalid Apple identity token',
    )
  })

  it('throws UnauthorizedHttpException for an expired token', async () => {
    const fixture = await createAppleToken(
      {
        sub: 'apple-user-1',
        email: 'parent@example.com',
      },
      { expiresIn: '-1 sec' },
    )
    const { provider } = createProvider(fixture.publicJwk)

    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(
      'Invalid Apple identity token',
    )
  })

  it('throws when the token header has no matching kid after a refetch', async () => {
    const fixture = await createAppleToken(
      {
        sub: 'apple-user-1',
        email: 'parent@example.com',
      },
      { kid: 'missing-key' },
    )
    const { provider, calls } = createProvider({ ...fixture.publicJwk, kid: 'other-key' })
    const verification = provider.verify(fixture.identityToken)

    await expect(verification).rejects.toThrow(UnauthorizedHttpException)
    await expect(verification).rejects.toThrow('Invalid Apple identity token')
    expect(calls).toEqual([JWKS_ENDPOINT, JWKS_ENDPOINT])
  })

  it('throws when required payload fields are missing', async () => {
    const fixture = await createAppleToken({
      sub: 'apple-user-1',
    })
    const { provider } = createProvider(fixture.publicJwk)

    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify(fixture.identityToken)).rejects.toThrow(
      'Invalid Apple token payload',
    )
  })

  it('returns the first-sign-in name when provided as a string or name parts', async () => {
    const fixture = await createAppleToken({
      sub: 'apple-user-1',
      email: 'parent@example.com',
    })
    const { provider } = createProvider(fixture.publicJwk)

    await expect(
      provider.verify(fixture.identityToken, { name: 'Parent User' }),
    ).resolves.toMatchObject({
      name: 'Parent User',
    })
    await expect(
      provider.verify(fixture.identityToken, { name: { firstName: 'Parent', lastName: 'User' } }),
    ).resolves.toMatchObject({
      name: 'Parent User',
    })
  })

  it('converts email_verified and is_private_email string and boolean claims to booleans', async () => {
    for (const claims of [
      { email_verified: 'true', is_private_email: 'true' },
      { email_verified: true, is_private_email: true },
    ] as const) {
      const fixture = await createAppleToken({
        sub: 'apple-user-1',
        email: 'parent@example.com',
        ...claims,
      })
      const { provider } = createProvider(fixture.publicJwk)

      await expect(provider.verify(fixture.identityToken)).resolves.toMatchObject({
        emailVerified: true,
        isPrivateEmail: true,
      })
    }
  })
})

function createProvider(
  publicJwk: JWK,
  options: { readonly now?: () => number } = {},
): { readonly provider: AppleProvider; readonly calls: string[] } {
  const calls: string[] = []
  const fetcher: typeof globalThis.fetch = async (input) => {
    calls.push(String(input))
    return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200 })
  }
  return {
    calls,
    provider: new AppleProvider({
      clientId: CLIENT_ID,
      jwksEndpoint: JWKS_ENDPOINT,
      fetch: fetcher,
      now: options.now,
    }),
  }
}

async function createAppleToken(
  claims: Record<string, unknown>,
  options: {
    readonly audience?: string
    readonly expiresIn?: string
    readonly issuer?: string
    readonly kid?: string
  } = {},
): Promise<AppleTokenFixture> {
  const kid = options.kid ?? 'apple-key-1'
  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const publicJwk = await toPublicJwk(publicKey, kid)
  const identityToken = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? CLIENT_ID)
    .setExpirationTime(options.expiresIn ?? '1 hour')
    .sign(privateKey)

  return { identityToken, publicJwk }
}

async function toPublicJwk(publicKey: KeyLike, kid: string): Promise<JWK> {
  const jwk = await exportJWK(publicKey)
  return {
    ...jwk,
    alg: 'RS256',
    kid,
    use: 'sig',
  }
}
