import { UnauthorizedHttpException } from '@atlex/core'
import { describe, expect, it } from 'vitest'

import { GoogleProvider } from '../src/providers/GoogleProvider.js'

describe('GoogleProvider', () => {
  it('calls tokeninfo with encoded id_token and returns a Google social user', async () => {
    const calls: string[] = []
    const payload = {
      aud: 'client-123',
      sub: 'google-user-1',
      email: 'parent@example.com',
      email_verified: 'true',
      name: 'Parent User',
      picture: 'https://example.com/avatar.png',
    }
    const fetcher: typeof globalThis.fetch = async (input) => {
      calls.push(String(input))
      return new Response(JSON.stringify(payload), { status: 200 })
    }
    const provider = new GoogleProvider({
      clientId: 'client-123',
      tokenInfoEndpoint: 'https://google.test/tokeninfo',
      fetch: fetcher,
    })

    const user = await provider.verify('token with spaces')

    expect(calls).toEqual(['https://google.test/tokeninfo?id_token=token%20with%20spaces'])
    expect(user).toEqual({
      provider: 'google',
      providerId: 'google-user-1',
      googleId: 'google-user-1',
      email: 'parent@example.com',
      emailVerified: true,
      name: 'Parent User',
      avatarUrl: 'https://example.com/avatar.png',
      raw: payload,
    })
  })

  it('validates the audience claim against the configured client id', async () => {
    const fetcher: typeof globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          aud: 'other-client',
          sub: 'google-user-1',
          email: 'parent@example.com',
          email_verified: true,
        }),
        { status: 200 },
      )
    const provider = new GoogleProvider({ clientId: 'client-123', fetch: fetcher })

    await expect(provider.verify('id-token')).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify('id-token')).rejects.toThrow('Google token audience mismatch')
  })

  it('throws when Google rejects an invalid or expired token', async () => {
    const fetcher: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ error: 'invalid_token' }), { status: 400 })
    const provider = new GoogleProvider({ clientId: 'client-123', fetch: fetcher })

    await expect(provider.verify('id-token')).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify('id-token')).rejects.toThrow('Invalid Google ID token')
  })

  it('throws when required payload fields are missing', async () => {
    const fetcher: typeof globalThis.fetch = async () =>
      new Response(JSON.stringify({ aud: 'client-123', email_verified: true }), { status: 200 })
    const provider = new GoogleProvider({ clientId: 'client-123', fetch: fetcher })

    await expect(provider.verify('id-token')).rejects.toThrow(UnauthorizedHttpException)
    await expect(provider.verify('id-token')).rejects.toThrow('Invalid Google token payload')
  })

  it('converts string and boolean email_verified claims to booleans', async () => {
    for (const emailVerified of ['true', true] as const) {
      const fetcher: typeof globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            aud: 'client-123',
            sub: 'google-user-1',
            email: 'parent@example.com',
            email_verified: emailVerified,
          }),
          { status: 200 },
        )
      const provider = new GoogleProvider({ clientId: 'client-123', fetch: fetcher })

      await expect(provider.verify('id-token')).resolves.toMatchObject({ emailVerified: true })
    }
  })
})
