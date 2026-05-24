import { readFile, appendFile } from 'node:fs/promises'
import { AuditLog } from '../audit-log.js'
import { KxcoPqAuditError } from '../errors.js'

export class FileAuditLog extends AuditLog {
  #path

  constructor({ keypair, path }) {
    super({ keypair })
    if (!path) throw new KxcoPqAuditError('FileAuditLog: path is required')
    this.#path = path
  }

  async _entries() {
    let text
    try { text = await readFile(this.#path, 'utf8') } catch { return [] }
    return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
  }

  async _store(entry) {
    await appendFile(this.#path, JSON.stringify(entry) + '\n', 'utf8')
  }
}
