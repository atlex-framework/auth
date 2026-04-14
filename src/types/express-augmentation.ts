import type { AuthorizationResponse } from '../authorization/AuthorizationResponse.js'
import type { Gate } from '../authorization/Gate.js'
import type { Authenticatable } from '../contracts/Authenticatable.js'
import type { Session } from '../session/Session.js'

declare global {
  namespace Express {
    interface Request {
      /** Populated by {@link StartSession}. */
      session?: Session
      /** Authenticated principal from {@link AuthMiddleware}. */
      user?: Authenticatable
      /** Authorization gate (optional; {@link AuthServiceProvider} binds via `auth.context`). */
      gate?: Gate
      /** Last successful guard name from {@link AuthManager.shouldUse}. */
      atlexAuthGuard?: string
      /** Requires {@link attachAuthorizesRequests}. */
      can?(ability: string, ...args: unknown[]): Promise<boolean>
      /** Requires {@link attachAuthorizesRequests}. */
      cannot?(ability: string, ...args: unknown[]): Promise<boolean>
      /** Requires {@link attachAuthorizesRequests}. */
      authorize?(ability: string, ...args: unknown[]): Promise<AuthorizationResponse>
    }
  }
}

export {}
