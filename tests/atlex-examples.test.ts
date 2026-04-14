import { describe, expect, it } from 'vitest'

import { AuthorizationResponse } from '../src/authorization/AuthorizationResponse.js'
import { parseDurationToSeconds } from '../src/jwt/parseDuration.js'
import { MemoryBlacklistStore } from '../src/jwt/MemoryBlacklistStore.js'

describe('@atlex/auth examples', () => {
  it('AuthorizationResponse allow', () => {
    const r = AuthorizationResponse.allow('ok')
    expect(r.allowed()).toBe(true)
  })

  it('AuthorizationResponse deny', () => {
    const r = AuthorizationResponse.deny('nope')
    expect(r.denied()).toBe(true)
  })

  it('parseDurationToSeconds parses minutes', () => {
    expect(parseDurationToSeconds('5m')).toBe(300)
  })

  it('MemoryBlacklistStore starts empty', async () => {
    const s = new MemoryBlacklistStore()
    expect(await s.has('x')).toBe(false)
  })

  it('MemoryBlacklistStore set and has', async () => {
    const s = new MemoryBlacklistStore()
    await s.set('t', 120)
    expect(await s.has('t')).toBe(true)
  })
})
