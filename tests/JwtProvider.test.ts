import { describe, expect, it } from 'vitest'

import { defaultAuthConfig } from '../src/config/defaultAuthConfig.js'
import { JwtProvider } from '../src/jwt/JwtProvider.js'

describe('JwtProvider', () => {
  it('signs and verifies HS256 access tokens', async () => {
    const cfg = defaultAuthConfig()
    const jwt = new JwtProvider(cfg.jwt)
    const token = await jwt.sign({ sub: '1', typ: 'access' })
    const payload = await jwt.verify(token)
    expect(payload.sub).toBe('1')
    expect(typeof payload.jti).toBe('string')
  })

  it('exposes jti via getJti', async () => {
    const cfg = defaultAuthConfig()
    const jwt = new JwtProvider(cfg.jwt)
    const token = await jwt.sign({ sub: '1', typ: 'access' })
    expect(jwt.getJti(token).length).toBeGreaterThan(0)
  })
})
