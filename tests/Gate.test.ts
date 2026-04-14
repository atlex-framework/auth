import { describe, expect, it } from 'vitest'

import { AuthorizationResponse } from '../src/authorization/AuthorizationResponse.js'
import { Gate } from '../src/authorization/Gate.js'
import { Policy } from '../src/authorization/Policy.js'
import type { Authenticatable } from '../src/contracts/Authenticatable.js'

class User implements Authenticatable {
  public constructor(private readonly id: number) {}
  public getAuthIdentifierName(): string {
    return 'id'
  }
  public getAuthIdentifier(): number {
    return this.id
  }
  public getAuthPassword(): string {
    return 'x'
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

class PostPolicy extends Policy {
  public before(user: Authenticatable): boolean | null {
    if (user.getAuthIdentifier() === 99) {
      return true
    }
    return null
  }

  public update(_user: Authenticatable, _post: unknown): boolean {
    return true
  }
}

describe('Gate', () => {
  it('runs before() short-circuit', async () => {
    const gate = new Gate(
      async () => new User(99),
      <T extends Policy>(C: new () => T) => new C(),
    )
    gate.resource('post', PostPolicy, ['update'])
    expect(await gate.allows('post.update', {})).toBe(true)
  })

  it('inspect returns AuthorizationResponse', async () => {
    const gate = new Gate(
      async () => new User(1),
      <T extends Policy>(C: new () => T) => new C(),
    )
    gate.define('edit', (user) => user !== null)
    const res = await gate.inspect('edit')
    expect(res).toBeInstanceOf(AuthorizationResponse)
    expect(res.allowed()).toBe(true)
  })
})
