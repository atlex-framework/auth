import { describe, expect, it } from 'vitest'

import { RefreshTokenRepository } from '../src/jwt/RefreshTokenRepository.js'

type InsertRow = Record<string, unknown>

class FakeQueryBuilder {
  public table(_name: string): this {
    return this
  }

  public async insert(data: InsertRow | InsertRow[]): Promise<number> {
    if (!Array.isArray(data)) {
      throw new Error('expected bulk insert array')
    }
    expect(data).toHaveLength(1)
    expect((data[0] as InsertRow).jti).toBe('jti_1')
    return 1
  }
}

describe('RefreshTokenRepository (database mode)', () => {
  it('inserts without assuming an id column', async () => {
    const repo = new RefreshTokenRepository({
      mode: 'database',
      table: 'refresh_tokens',
      query: () => new FakeQueryBuilder() as unknown as import('@atlex/orm').QueryBuilder,
    })

    await expect(
      repo.create(1, 'fam_1', 'jti_1', new Date(Date.now() + 60_000)),
    ).resolves.toBeUndefined()
  })
})
