import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto'

import type { SessionStore } from '../../contracts/SessionStore.js'
import { parseCookies } from '../../support/parseCookies.js'
import { secureCompare } from '../../support/secureCompare.js'

/**
 * Cookie-backed session: the serialized payload lives entirely in the session cookie.
 *
 * When `encrypt` is true, the payload is AES-256-GCM encrypted; otherwise it is signed with HMAC-SHA256.
 */
export class CookieStore implements SessionStore {
  private readonly secret: Uint8Array

  private readonly encrypt: boolean

  private incomingCookie = ''

  private outgoingPayload = ''

  /**
   * @param secretKey - Application secret (UTF-8) used for signing/encryption.
   * @param encrypt - When true, encrypt payload; when false, sign only.
   */
  public constructor(secretKey: string, encrypt: boolean) {
    this.secret = new TextEncoder().encode(secretKey)
    this.encrypt = encrypt
  }

  /**
   * Captures the raw `Cookie` header for {@link CookieStore.read}.
   *
   * @param cookieHeader - `Cookie` header value.
   * @param cookieName - Session cookie name.
   */
  public setIncoming(cookieHeader: string | undefined, cookieName: string): void {
    const jar = parseCookies(cookieHeader)
    this.incomingCookie = jar[cookieName] ?? ''
  }

  /**
   * @returns Payload to set on `Set-Cookie` after {@link CookieStore.write}.
   */
  public getOutgoingCookieValue(): string {
    return this.outgoingPayload
  }

  /**
   * @inheritdoc
   */
  public async open(_savePath: string, _sessionName: string): Promise<void> {
    /* session name is applied via setIncoming for cookie transport */
  }

  /**
   * @inheritdoc
   */
  public async close(): Promise<void> {
    /* noop */
  }

  /**
   * @inheritdoc
   */
  public async read(_sessionId: string): Promise<string> {
    if (this.incomingCookie.length === 0) {
      return ''
    }
    try {
      return unpack(this.incomingCookie, this.secret, this.encrypt)
    } catch {
      return ''
    }
  }

  /**
   * @inheritdoc
   */
  public async write(_sessionId: string, data: string): Promise<void> {
    this.outgoingPayload = pack(data, this.secret, this.encrypt)
  }

  /**
   * @inheritdoc
   */
  public async destroy(_sessionId: string): Promise<void> {
    this.outgoingPayload = ''
  }

  /**
   * @inheritdoc
   */
  public async gc(_maxLifetime: number): Promise<number> {
    return 0
  }
}

function pack(data: string, secret: Uint8Array, encrypt: boolean): string {
  if (encrypt) {
    const iv = randomBytes(12)
    const key = deriveKey(secret, 32)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const enc = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    const blob = Buffer.concat([iv, tag, enc]).toString('base64url')
    const sig = sign(blob, secret)
    return `${blob}.${sig}`
  }
  const blob = Buffer.from(data, 'utf8').toString('base64url')
  const sig = sign(blob, secret)
  return `${blob}.${sig}`
}

function unpack(token: string, secret: Uint8Array, encrypt: boolean): string {
  const lastDot = token.lastIndexOf('.')
  if (lastDot <= 0) {
    throw new Error('Malformed session cookie')
  }
  const blob = token.slice(0, lastDot)
  const sig = token.slice(lastDot + 1)
  if (!secureCompare(sign(blob, secret), sig)) {
    throw new Error('Bad session cookie signature')
  }
  if (encrypt) {
    const raw = Buffer.from(blob, 'base64url')
    const iv = raw.subarray(0, 12)
    const tag = raw.subarray(12, 28)
    const enc = raw.subarray(28)
    const key = deriveKey(secret, 32)
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8')
  }
  return Buffer.from(blob, 'base64url').toString('utf8')
}

function sign(blob: string, secret: Uint8Array): string {
  return createHmac('sha256', secret).update(blob).digest('base64url')
}

function deriveKey(secret: Uint8Array, length: number): Buffer {
  return createHmac('sha256', secret).update('atlex-session-key').digest().subarray(0, length)
}
