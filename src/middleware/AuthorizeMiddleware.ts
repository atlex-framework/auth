import type { NextFunction, Request, RequestHandler, Response } from 'express'

import type { Gate } from '../authorization/Gate.js'

/**
 * Authorizes the current user against a gate ability (and optional route parameters).
 */
export class AuthorizeMiddleware {
  private readonly gate: Gate

  /**
   * @param gate - Authorization gate.
   */
  public constructor(gate: Gate) {
    this.gate = gate
  }

  /**
   * @param ability - Registered ability / policy method mapping.
   * @param modelParamKeys - Route parameter names passed as gate arguments after the user.
   * @returns Express middleware.
   */
  public handle(ability: string, ...modelParamKeys: string[]): RequestHandler {
    return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
      try {
        const models = modelParamKeys.map((k) => req.params[k])
        await this.gate.authorize(ability, ...models)
        next()
      } catch (err) {
        next(err)
      }
    }
  }
}
