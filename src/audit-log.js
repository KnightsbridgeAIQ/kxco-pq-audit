import { mlDsa } from 'kxco-post-quantum'
import { sha256 } from '@noble/hashes/sha2'
import { KxcoPqAuditError } from './errors.js'

const enc = new TextEncoder()

function b64url(bytes)  { return Buffer.from(bytes).toString('base64url') }
function fromB64url(s)  { return new Uint8Array(Buffer.from(s, 'base64url')) }

function hashEntry(entry) {
  return b64url(sha256(enc.encode(JSON.stringify(entry))))
}

function signingBytes(seq, timestamp, operation, metadata, prevHash) {
  return enc.encode(
    `kxco-audit-v1\n${seq}\n${timestamp}\n${operation}\n${prevHash ?? 'null'}\n${JSON.stringify(metadata)}`
  )
}

export class AuditLog {
  #keypair
  #entries = []
  #chain
  #checkpointEvery
  #institutionKid

  constructor({ keypair, chain, checkpointEvery = 100, institutionKid } = {}) {
    if (!keypair?.secretKey || !keypair?.publicKey) {
      throw new KxcoPqAuditError('keypair with secretKey and publicKey is required')
    }
    this.#keypair         = keypair
    this.#chain           = chain           ?? null
    this.#checkpointEvery = checkpointEvery
    this.#institutionKid  = institutionKid  ?? null
  }

  async append(operation, metadata = {}) {
    if (typeof operation !== 'string' || !operation) {
      throw new KxcoPqAuditError('operation must be a non-empty string')
    }
    const all  = await this._entries()
    const seq  = all.length
    const ts   = new Date().toISOString()
    const prev = seq === 0 ? null : hashEntry(all[seq - 1])
    const msg  = signingBytes(seq, ts, operation, metadata, prev)
    const sig  = mlDsa.ml_dsa65.sign(new Uint8Array(this.#keypair.secretKey), msg)

    const entry = { seq, timestamp: ts, operation, metadata, prevHash: prev, signature: b64url(sig) }
    await this._store(entry)

    const entryCount = seq + 1
    if (this.#chain && entryCount % this.#checkpointEvery === 0) {
      const rootHash = hashEntry(entry)
      const kid      = this.#institutionKid ?? b64url(this.#keypair.publicKey).slice(0, 16)
      this.#chain.anchorAuditRoot({ rootHash, entryCount }).catch((err) => {
        console.warn(`[kxco-pq-audit] chain checkpoint failed (entry ${entryCount}): ${err.message}`)
      })
    }

    return entry
  }

  async verify(publicKey) {
    const all = await this._entries()
    for (let i = 0; i < all.length; i++) {
      const e = all[i]
      if (i === 0) {
        if (e.prevHash !== null) return { valid: false, error: 'entry 0: prevHash must be null' }
      } else {
        const expected = hashEntry(all[i - 1])
        if (e.prevHash !== expected) return { valid: false, error: `entry ${i}: prevHash mismatch` }
      }
      const msg = signingBytes(e.seq, e.timestamp, e.operation, e.metadata, e.prevHash)
      let ok
      try { ok = mlDsa.ml_dsa65.verify(new Uint8Array(publicKey), msg, fromB64url(e.signature)) }
      catch { ok = false }
      if (!ok) return { valid: false, error: `entry ${i}: signature invalid` }
    }
    return { valid: true, count: all.length }
  }

  async export() {
    return this._entries()
  }

  async _entries() { return [...this.#entries] }
  async _store(entry) { this.#entries.push(entry) }
}
