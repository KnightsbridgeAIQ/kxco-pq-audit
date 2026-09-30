import { createReadStream } from 'node:fs'
import { readFile, appendFile, open, stat } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { AuditLog } from '../audit-log.js'
import { KxcoPqAuditError } from '../errors.js'

/** An entry or a seal is a JSON object: not null, not an array, not a scalar. */
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/**
 * Append-only NDJSON backend.
 *
 * Entries are read as a stream, never all at once, so appending and verifying
 * both stay flat as the file grows. Seals go to `<path>.seals`, so a reader
 * that only knows about entries is unaffected by a sealed log.
 *
 * Writes go through one handle held open for the life of the instance, which
 * costs ~46us an entry against ~421us for reopening the file every time. Call
 * `close()` when done with the log; the data is already with the OS either way,
 * so a missed close leaks a descriptor and nothing else.
 *
 * One file has one writer. A signed chain cannot have two: both would build on
 * the same tail, and the second entry would take the first one's place. The
 * size the file should be is recorded on open and checked whenever the log
 * seals or closes, so a second writer surfaces as an error rather than as a
 * chain that only fails much later at verify().
 */
export class FileAuditLog extends AuditLog {
  #path
  #sealPath
  #handle = null
  #size = null
  #idleTimer = null
  #idleMs

  constructor({ keypair, path, chain, checkpointEvery, institutionKid, sealed, idleReleaseMs = 2000 }) {
    super({ keypair, chain, checkpointEvery, institutionKid, sealed })
    if (!path) throw new KxcoPqAuditError('FileAuditLog: path is required')
    this.#path     = path
    this.#sealPath = path + '.seals'
    this.#idleMs   = idleReleaseMs
  }

  async *_iterate() {
    let stream
    try {
      stream = createReadStream(this.#path, { encoding: 'utf8' })
      await new Promise((resolve, reject) => {
        stream.once('readable', resolve)
        stream.once('end', resolve)
        stream.once('error', reject)
      })
    } catch (err) {
      if (err.code === 'ENOENT') return
      throw err
    }

    const lines = createInterface({ input: stream, crlfDelay: Infinity })
    let lineNo = 0
    try {
      for await (const line of lines) {
        lineNo++
        if (!line) continue
        let entry
        try {
          entry = JSON.parse(line)
        } catch {
          // A line that will not parse is either a torn write from a crash or
          // an edit. Either way it is not something to skip past in silence.
          throw new KxcoPqAuditError(
            `${this.#path}: line ${lineNo} is not valid JSON. ` +
            'A partial last line is an interrupted append and can be truncated; ' +
            'anywhere else means the file was edited.'
          )
        }
        // JSON that is not an object cannot be an entry, and a torn write never
        // produces one, since every entry line starts with `{`.
        if (!isRecord(entry)) {
          throw new KxcoPqAuditError(
            `${this.#path}: line ${lineNo} is JSON but not an audit entry, which means the file was edited.`
          )
        }
        yield entry
      }
    } finally {
      lines.close()
      stream.destroy()
    }
  }

  async _entries() {
    const out = []
    for await (const entry of this._iterate()) out.push(entry)
    return out
  }

  async _store(entry) {
    const line = JSON.stringify(entry) + '\n'
    const handle = await this.#open()
    await handle.write(line, null, 'utf8')
    this.#size += Buffer.byteLength(line, 'utf8')
    this.#idleRelease()
  }

  /**
   * Let go of the handle once writing stops.
   *
   * A busy log never goes idle and keeps the fast path. A short-lived one hands
   * the descriptor back on its own, so forgetting `close()` costs nothing
   * instead of failing when the handle is finally collected. The timer is
   * unref'd, so it never holds the process open, and it holds a reference to
   * this log, so the handle cannot be collected while a release is pending.
   */
  #idleRelease() {
    clearTimeout(this.#idleTimer)
    this.#idleTimer = setTimeout(() => { this.close().catch(() => {}) }, this.#idleMs)
    this.#idleTimer.unref?.()
  }

  async _seals() {
    let text
    try { text = await readFile(this.#sealPath, 'utf8') } catch { return [] }
    // Read line by line, so a torn or edited seal is named the same way a bad
    // entry line is. A line may end in \r if the file was edited with CRLF.
    const seals = []
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].endsWith('\r') ? lines[i].slice(0, -1) : lines[i]
      if (!line) continue
      let seal
      try {
        seal = JSON.parse(line)
      } catch {
        throw new KxcoPqAuditError(
          `${this.#sealPath}: line ${i + 1} is not valid JSON. ` +
          'A partial last line is an interrupted seal and can be truncated; ' +
          'anywhere else means the file was edited.'
        )
      }
      if (!isRecord(seal)) {
        throw new KxcoPqAuditError(
          `${this.#sealPath}: line ${i + 1} is JSON but not a seal, which means the file was edited.`
        )
      }
      seals.push(seal)
    }
    return seals
  }

  async _storeSeal(seal) {
    await this.assertSoleWriter()
    await appendFile(this.#sealPath, JSON.stringify(seal) + '\n', 'utf8')
  }

  /**
   * Throw if the entry file is not the size this instance left it. Runs on open
   * and on every seal; call it directly to check at any other point.
   */
  async assertSoleWriter() {
    if (this.#size === null) return
    let actual = 0
    try { actual = (await stat(this.#path)).size } catch (err) {
      if (err.code !== 'ENOENT') throw err
    }
    if (actual !== this.#size) {
      throw new KxcoPqAuditError(
        `${this.#path}: file is ${actual} bytes, expected ${this.#size}. ` +
        'Something else wrote to this log. Appending now would fork the chain, ' +
        'so open a new instance to pick up the current tail.'
      )
    }
  }

  /** Release the write handle. Safe to call more than once, and after any write. */
  async close() {
    clearTimeout(this.#idleTimer)
    this.#idleTimer = null
    if (!this.#handle) return
    const handle = this.#handle
    this.#handle = null
    try { await this.assertSoleWriter() } finally { await handle.close() }
  }

  async #open() {
    if (this.#handle) return this.#handle
    try { this.#size = (await stat(this.#path)).size } catch (err) {
      if (err.code !== 'ENOENT') throw err
      this.#size = 0
    }
    this.#handle = await open(this.#path, 'a')
    return this.#handle
  }
}
