import type { Constructor } from '@atlex/core'

import type { Authenticatable } from '../contracts/Authenticatable.js'

import { AuthorizationResponse } from './AuthorizationResponse.js'
import { type Policy } from './Policy.js'

export type AbilityCallback = (
  user: Authenticatable | null,
  ...args: unknown[]
) => boolean | AuthorizationResponse | Promise<boolean | AuthorizationResponse>

export type BeforeCallback = (
  user: Authenticatable | null,
  ability: string,
  ...args: unknown[]
) => boolean | null | undefined | Promise<boolean | null | undefined>

export type AfterCallback = (
  user: Authenticatable | null,
  ability: string,
  result: boolean,
  ...args: unknown[]
) => boolean | undefined | Promise<boolean | undefined>

/**
 * Authorization gate: closures, policies, and global hooks.
 */
export class Gate {
  private readonly abilitiesMap = new Map<string, AbilityCallback>()

  private readonly policiesMap = new Map<Constructor<object>, Constructor<Policy>>()

  private readonly resourcePolicies = new Map<
    string,
    { policy: Constructor<Policy>; abilities: string[] }
  >()

  private readonly beforeHooks: BeforeCallback[] = []

  private readonly afterHooks: AfterCallback[] = []

  private readonly currentUser: () => Promise<Authenticatable | null>

  private readonly resolvePolicy: <T extends Policy>(c: Constructor<T>) => T

  /**
   * @param currentUser - Returns the authenticated user (or null).
   * @param resolvePolicy - Instantiates a policy class (usually via IoC).
   */
  public constructor(
    currentUser: () => Promise<Authenticatable | null>,
    resolvePolicy: <T extends Policy>(c: Constructor<T>) => T,
  ) {
    this.currentUser = currentUser
    this.resolvePolicy = resolvePolicy
  }

  /**
   * Registers a closure ability.
   */
  public define(ability: string, callback: AbilityCallback): this {
    this.abilitiesMap.set(ability, callback)
    return this
  }

  /**
   * Registers a resource policy mapping (`post.view`, `post.update`, ...).
   */
  public resource(name: string, policyClass: Constructor<Policy>, abilities?: string[]): this {
    const abs = abilities ?? [
      'viewAny',
      'view',
      'create',
      'update',
      'delete',
      'restore',
      'forceDelete',
    ]
    this.resourcePolicies.set(name, { policy: policyClass, abilities: abs })
    for (const a of abs) {
      const ability = `${name}.${a}`
      this.abilitiesMap.set(
        ability,
        async (user, ...args) => await this.invokePolicyMethod(policyClass, a, user, args),
      )
    }
    return this
  }

  /**
   * Maps a model constructor to a policy class.
   */
  public policy(model: Constructor<object>, policyClass: Constructor<Policy>): this {
    this.policiesMap.set(model, policyClass)
    return this
  }

  /**
   * Resolves a policy for an arbitrary model instance.
   */
  public getPolicyFor(model: object): Policy | null {
    const ctor = model.constructor as Constructor<object>
    const P = this.policiesMap.get(ctor)
    return P === undefined ? null : this.resolvePolicy(P)
  }

  /**
   * Global pre-authorization hook.
   */
  public before(callback: BeforeCallback): this {
    this.beforeHooks.push(callback)
    return this
  }

  /**
   * Global post-authorization hook.
   */
  public after(callback: AfterCallback): this {
    this.afterHooks.push(callback)
    return this
  }

  /**
   * @returns True when the ability passes for the current user.
   */
  public async allows(ability: string, ...args: unknown[]): Promise<boolean> {
    const res = await this.inspect(ability, ...args)
    return res.allowed()
  }

  /**
   * @returns Inverse of {@link Gate.allows}.
   */
  public async denies(ability: string, ...args: unknown[]): Promise<boolean> {
    return !(await this.allows(ability, ...args))
  }

  /**
   * @returns True when every ability passes.
   */
  public async check(abilities: string[], args?: unknown[]): Promise<boolean> {
    for (const a of abilities) {
      if (!(await this.allows(a, ...(args ?? [])))) {
        return false
      }
    }
    return true
  }

  /**
   * @returns True when any ability passes.
   */
  public async any(abilities: string[], args?: unknown[]): Promise<boolean> {
    for (const a of abilities) {
      if (await this.allows(a, ...(args ?? []))) {
        return true
      }
    }
    return false
  }

  /**
   * Throws {@link AuthorizationError} when denied.
   */
  public async authorize(ability: string, ...args: unknown[]): Promise<AuthorizationResponse> {
    const res = await this.inspect(ability, ...args)
    res.authorize()
    return res
  }

  /**
   * Returns a structured response without throwing.
   */
  public async inspect(ability: string, ...args: unknown[]): Promise<AuthorizationResponse> {
    return await this.inspectForUser(await this.currentUser(), ability, [...args])
  }

  /**
   * Like {@link Gate.inspect} but uses an explicit user (e.g. {@link Gate.forUser}).
   *
   * @param user - User context (guest checks pass `null`).
   * @param ability - Ability name.
   * @param args - Additional arguments (models, ids, ...).
   */
  public async inspectForUser(
    user: Authenticatable | null,
    ability: string,
    args: unknown[],
  ): Promise<AuthorizationResponse> {
    for (const hook of this.beforeHooks) {
      const r = await hook(user, ability, ...args)
      if (r === true) {
        return AuthorizationResponse.allow()
      }
      if (r === false) {
        return AuthorizationResponse.deny()
      }
    }
    let result = await this.runAbility(ability, user, args)
    for (const hook of this.afterHooks) {
      const r = await hook(user, ability, result, ...args)
      if (r !== undefined) {
        result = r
      }
    }
    return result ? AuthorizationResponse.allow() : AuthorizationResponse.deny()
  }

  /**
   * @returns Gate scoped to a concrete user (ignores the ambient request user).
   */
  public forUser(user: Authenticatable): GateForUser {
    return new GateForUser(this, user)
  }

  /**
   * @returns Registered closure abilities.
   */
  public abilities(): Record<string, AbilityCallback> {
    return Object.fromEntries(this.abilitiesMap)
  }

  /**
   * @returns Registered explicit policy mappings.
   */
  public policies(): Map<Constructor<object>, Constructor<Policy>> {
    return new Map(this.policiesMap)
  }

  /**
   * @returns True when a closure ability exists.
   */
  public has(ability: string): boolean {
    return this.abilitiesMap.has(ability)
  }

  private async runAbility(
    ability: string,
    user: Authenticatable | null,
    args: unknown[],
  ): Promise<boolean> {
    const fn = this.abilitiesMap.get(ability)
    if (fn === undefined) {
      return false
    }
    const raw = await fn(user, ...args)
    return await normalizePolicyResult(raw)
  }

  private async invokePolicyMethod(
    policyClass: Constructor<Policy>,
    method: string,
    user: Authenticatable | null,
    args: unknown[],
  ): Promise<boolean> {
    if (user === null) {
      return false
    }
    const policy = this.resolvePolicy(policyClass)
    const before = policy.before?.bind(policy)
    if (before !== undefined) {
      const b = await before(user, method)
      if (b === true) {
        return true
      }
      if (b === false) {
        return false
      }
    }
    const fn = (policy as Record<string, unknown>)[method]
    if (typeof fn !== 'function') {
      return false
    }
    const raw: unknown = await (fn as (...a: unknown[]) => unknown).call(policy, user, ...args)
    let allowed = await normalizePolicyResult(
      raw as boolean | AuthorizationResponse | Promise<boolean | AuthorizationResponse>,
    )
    const after = policy.after?.bind(policy)
    if (after !== undefined) {
      const a = await after(user, method, allowed)
      if (a !== undefined) {
        allowed = a
      }
    }
    return allowed
  }
}

async function normalizePolicyResult(
  raw: boolean | AuthorizationResponse | Promise<boolean | AuthorizationResponse>,
): Promise<boolean> {
  const v = await raw
  if (typeof v === 'boolean') {
    return v
  }
  if (v instanceof AuthorizationResponse) {
    return v.allowed()
  }
  return false
}

/**
 * Gate scoped to a fixed {@link Authenticatable} instance.
 */
export class GateForUser {
  private readonly gate: Gate

  private readonly user: Authenticatable

  /**
   * @param gate - Parent gate.
   * @param user - Fixed user.
   */
  public constructor(gate: Gate, user: Authenticatable) {
    this.gate = gate
    this.user = user
  }

  /**
   * @returns True when the ability passes for the fixed user.
   */
  public async allows(ability: string, ...args: unknown[]): Promise<boolean> {
    const res = await this.inspect(ability, ...args)
    return res.allowed()
  }

  /**
   * @returns Structured inspection for the fixed user.
   */
  public async inspect(ability: string, ...args: unknown[]): Promise<AuthorizationResponse> {
    return await this.gate.inspectForUser(this.user, ability, [...args])
  }

  /**
   * Throws when denied for the fixed user.
   */
  public async authorize(ability: string, ...args: unknown[]): Promise<AuthorizationResponse> {
    const res = await this.inspect(ability, ...args)
    res.authorize()
    return res
  }
}
