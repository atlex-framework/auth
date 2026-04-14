import type { Authenticatable } from '../contracts/Authenticatable.js'

import type { AuthorizationResponse } from './AuthorizationResponse.js'

type PolicyResult = boolean | AuthorizationResponse | Promise<boolean | AuthorizationResponse>

/**
 * Base policy with optional `before` / `after` hooks and CRUD-style methods.
 */
export abstract class Policy {
  /**
   * Optional global gate executed before any ability method.
   *
   * @param user - Current user.
   * @param ability - Ability name being checked.
   * @returns `true` allow all, `false` deny, `null`/`undefined` continue to methods.
   */
  public before?(
    user: Authenticatable,
    ability: string,
  ): boolean | null | undefined | Promise<boolean | null | undefined>

  /**
   * Optional post-hook that may override the resolved boolean.
   */
  public after?(
    user: Authenticatable,
    ability: string,
    result: boolean,
  ): boolean | undefined | Promise<boolean | undefined>

  public viewAny?(user: Authenticatable): PolicyResult

  public view?(user: Authenticatable, model: unknown): PolicyResult

  public create?(user: Authenticatable): PolicyResult

  public update?(user: Authenticatable, model: unknown): PolicyResult

  public delete?(user: Authenticatable, model: unknown): PolicyResult

  public restore?(user: Authenticatable, model: unknown): PolicyResult

  public forceDelete?(user: Authenticatable, model: unknown): PolicyResult
}
