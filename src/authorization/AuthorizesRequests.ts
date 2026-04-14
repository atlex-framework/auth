import type { Request } from 'express'

import { AuthenticationError } from '../errors/AuthenticationError.js'

import type { AuthorizationResponse } from './AuthorizationResponse.js'
import type { Gate } from './Gate.js'

/**
 * Binds `can`, `cannot`, and `authorize` helpers onto an Express request using the active gate.
 *
 * @param req - Current request.
 * @param gate - Authorization gate.
 */
export function attachAuthorizesRequests(req: Request, gate: Gate): void {
  req.can = async (ability: string, ...args: unknown[]): Promise<boolean> => {
    const u = req.user
    if (u === undefined) {
      return false
    }
    return await gate.forUser(u).allows(ability, ...args)
  }

  req.cannot = async (ability: string, ...args: unknown[]): Promise<boolean> => {
    return !(await req.can!(ability, ...args))
  }

  req.authorize = async (ability: string, ...args: unknown[]): Promise<AuthorizationResponse> => {
    const u = req.user
    if (u === undefined) {
      throw new AuthenticationError('Unauthenticated')
    }
    return await gate.forUser(u).authorize(ability, ...args)
  }
}
