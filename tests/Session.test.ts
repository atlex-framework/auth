import { describe, expect, it } from 'vitest'

import { Session } from '../src/session/Session.js'
import { NullStore } from '../src/session/stores/NullStore.js'

describe('Session', () => {
  it('migrates session id and preserves payload', async () => {
    const store = new NullStore()
    const s = new Session(store, 'test')
    await store.open('', 'test')
    await s.start()
    s.put('a', 1)
    const oldId = s.getId()
    await s.migrate(false)
    expect(s.getId()).not.toBe(oldId)
    expect(s.get<number>('a')).toBe(1)
  })
})
