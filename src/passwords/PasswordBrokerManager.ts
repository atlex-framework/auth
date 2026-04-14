import type { PasswordBroker } from './PasswordBroker.js'

/**
 * Resolves configured {@link PasswordBroker} instances by name.
 */
export class PasswordBrokerManager {
  private readonly brokers: Record<string, PasswordBroker>

  /**
   * @param brokers - Map of broker name → instance.
   */
  public constructor(brokers: Record<string, PasswordBroker>) {
    this.brokers = brokers
  }

  /**
   * @param name - Broker key (`users` default).
   */
  public broker(name?: string): PasswordBroker {
    const key = name ?? 'users'
    const b = this.brokers[key]
    if (b === undefined) {
      throw new Error(`PasswordBrokerManager: unknown broker "${key}".`)
    }
    return b
  }
}
