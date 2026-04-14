import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { UserProvider } from '../contracts/UserProvider.js'
import { type HashManager } from '../hashing/HashManager.js'

type RetrieveByCredentials = (
  credentials: Record<string, unknown>,
) => Promise<Authenticatable | null>

/**
 * User provider backed by app-supplied callbacks (ideal for tests and custom stores).
 */
export class CallbackUserProvider implements UserProvider {
  private readonly hash: HashManager

  private readonly retrieve: RetrieveByCredentials

  /**
   * @param hash - Password hasher.
   * @param retrieve - Resolve a user from a credential bag.
   */
  public constructor(hash: HashManager, retrieve: RetrieveByCredentials) {
    this.hash = hash
    this.retrieve = retrieve
  }

  /**
   * @inheritdoc
   */
  public async retrieveById(id: string | number): Promise<Authenticatable | null> {
    return await this.retrieve({ id })
  }

  /**
   * @inheritdoc
   */
  public async retrieveByToken(
    id: string | number,
    token: string,
  ): Promise<Authenticatable | null> {
    const user = await this.retrieve({ id })
    if (user === null) {
      return null
    }
    const remember = user.getRememberToken()
    if (remember === null) {
      return null
    }
    return (await this.hash.check(token, remember)) ? user : null
  }

  /**
   * @inheritdoc
   */
  public async updateRememberToken(user: Authenticatable, token: string): Promise<void> {
    user.setRememberToken(token)
  }

  /**
   * @inheritdoc
   */
  public async retrieveByCredentials(
    credentials: Record<string, unknown>,
  ): Promise<Authenticatable | null> {
    return await this.retrieve(credentials)
  }

  /**
   * @inheritdoc
   */
  public async validateCredentials(
    user: Authenticatable,
    credentials: Record<string, unknown>,
  ): Promise<boolean> {
    const password = credentials.password
    if (typeof password !== 'string') {
      return false
    }
    return await this.hash.check(password, user.getAuthPassword())
  }
}
