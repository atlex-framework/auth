import { mkdir, readFile, readdir, rm, stat, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'

import type { SessionStore } from '../../contracts/SessionStore.js'

/**
 * File-based session store (one file per session id).
 */
export class FileStore implements SessionStore {
  private root = ''

  /**
   * @inheritdoc
   */
  public async open(savePath: string, _sessionName: string): Promise<void> {
    this.root = savePath
    await mkdir(this.root, { recursive: true })
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
  public async read(sessionId: string): Promise<string> {
    try {
      return await readFile(this.filePath(sessionId), 'utf8')
    } catch {
      return ''
    }
  }

  /**
   * @inheritdoc
   */
  public async write(sessionId: string, data: string): Promise<void> {
    const fp = this.filePath(sessionId)
    await mkdir(path.dirname(fp), { recursive: true })
    await writeFile(fp, data, 'utf8')
  }

  /**
   * @inheritdoc
   */
  public async destroy(sessionId: string): Promise<void> {
    try {
      await unlink(this.filePath(sessionId))
    } catch {
      /* missing file */
    }
  }

  /**
   * @inheritdoc
   */
  public async gc(maxLifetime: number): Promise<number> {
    const now = Date.now() / 1000
    let removed = 0
    let names: string[] = []
    try {
      names = await readdir(this.root)
    } catch {
      return 0
    }
    for (const name of names) {
      const fp = path.join(this.root, name)
      try {
        const st = await stat(fp)
        if (now - st.mtimeMs / 1000 > maxLifetime) {
          await rm(fp, { force: true })
          removed += 1
        }
      } catch {
        /* ignore */
      }
    }
    return removed
  }

  private filePath(sessionId: string): string {
    return path.join(this.root, `${sessionId}.session`)
  }
}
