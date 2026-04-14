import { describe, expect, it } from 'vitest'

import { DatabaseTokenRepository } from '../src/passwords/DatabaseTokenRepository.js'

type InsertRow = Record<string, unknown>

class FakeQueryBuilder {
  private op: 'delete' | 'insert' | null = null

  public table(_name: string): this {
    return this
  }

  public where(_col: string, _val: unknown): this {
    this.op = 'delete'
    return this
  }

  public async delete(): Promise<number> {
    return 0
  }

  public async insert(data: InsertRow | InsertRow[]): Promise<number> {
    if (!Array.isArray(data)) {
      throw new Error('expected bulk insert array')
    }
    expect(data).toHaveLength(1)
    expect((data[0] as InsertRow).email).toBe('u@example.com')
    return 1
  }
}

const user = {
  getEmailForPasswordReset: () => 'u@example.com',
}

describe('DatabaseTokenRepository', () => {
  it('inserts reset rows without assuming an id column', async () => {
    const repo = new DatabaseTokenRepository(
      () => new FakeQueryBuilder() as unknown as import('@atlex/orm').QueryBuilder,
      'password_resets',
      'k',
      60,
      60,
    )

    const token = await repo.create(
      user as import('../src/contracts/CanResetPassword.js').CanResetPassword,
    )
    expect(typeof token).toBe('string')
    expect(token.length).toBeGreaterThan(10)
  })
})
