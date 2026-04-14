import { describe, expect, it } from 'vitest'

import { defaultAuthConfig } from '../src/config/defaultAuthConfig.js'
import { HashManager } from '../src/hashing/HashManager.js'

describe('HashManager', () => {
  it('hashes and checks bcrypt', async () => {
    const cfg = defaultAuthConfig()
    const hash = new HashManager(cfg.hashing, 'bcrypt')
    const h = await hash.make('secret')
    expect(await hash.check('secret', h)).toBe(true)
    expect(await hash.check('wrong', h)).toBe(false)
  })
})
