import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { sha256 } from '@noble/hashes/sha2.js'
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

function sealBytes(fromSeq, toSeq, prevRoot, rootHash, timestamp) {
  return enc.encode(
    `kxco-audit-seal-v1\n${fromSeq}\n${toSeq}\n${prevRoot}\n${rootHash}\n${timestamp}`
  )
}

/** The first seal has no predecessor; this stands in for one so the seals chain too. */
const GENESIS_ROOT = '0'.repeat(64)

/**
 * Which key signed a record.
 *
 * `kid` is deliberately NOT part of the signed bytes. Including it would mean a
 * new signing-message version, and every log written by this package would stop
 * verifying under an older reader. Left out, it is a selector rather than a
 * claim: tampering with it makes verification select the wrong key and fail,
 * which is the same outcome tampering with anything else already produces. It
 * cannot make a forged record verify, because that still needs a key the
 * verifier was given.
 *
 * The consequence worth stating: a log written by this version verifies
 * unchanged under 1.3.x, and a log written by 1.3.x verifies here.
 */
function kidOf(publicKey) {
  return fingerprint(new Uint8Array(publicKey))
}

/**
 * Normalise whatever verify() was handed into a candidate list.
 *
 * One key keeps the original call shape working. An array is what a log that
 * outlived a key rotation needs, because no single key signed all of it.
 */
function candidatesFrom(publicKey) {
  const list = Array.isArray(publicKey) ? publicKey : [publicKey]
  if (list.length === 0) {
    throw new KxcoPqAuditError('verify: at least one public key is required')
  }
  return list.map((pk) => {
    if (!pk) throw new KxcoPqAuditError('verify: a public key was null or undefined')
    const bytes = new Uint8Array(pk)
    return { kid: kidOf(bytes), publicKey: bytes }
  })
}

function verifySignature(candidates, recordKid, msg, signatureB64, label) {
  const sigHex = () => Buffer.from(fromB64url(signatureB64)).toString('hex')

  // A record that names its key is checked against that key and no other.
  // Falling back to the rest would let a swapped kid pass under a different
  // key, which is not a forgery but is a confusing thing to report as valid.
  if (recordKid) {
    const match = candidates.find((c) => c.kid === recordKid)
    if (!match) {
      return {
        error: `${label}: signed by kid ${recordKid}, which was not among the ` +
               `${candidates.length} key(s) supplied`,
      }
    }
    let ok
    try { ok = mlDsa.verify(match.publicKey, msg, sigHex()) } catch { ok = false }
    return ok ? { kid: match.kid } : { error: `${label}: signature invalid` }
  }

  // No kid: a log written before this version. Try each key.
  for (const c of candidates) {
    let ok
    try { ok = mlDsa.verify(c.publicKey, msg, sigHex()) } catch { ok = false }
    if (ok) return { kid: c.kid }
  }
  return { error: `${label}: signature invalid` }
}

/**
 * A run's root: the previous seal's root followed by every entry hash in seq
 * order. Chaining the roots means removing a whole seal breaks the next one,
 * the same way removing an entry breaks the next entry's prevHash.
 */
function rootOf(prevRoot, entryHashes) {
  return b64url(sha256(enc.encode(prevRoot + entryHashes.join(''))))
}

/**
 * Tamper-evident append-only log.
 *
 * Appending costs the same whether the log holds ten entries or ten million:
 * a new entry needs the previous entry's hash and the next seq, never the log.
 * Verification streams, so it is bounded by one entry rather than by the log.
 */
export class AuditLog {
  #keypair
  #entries = []
  #sealsList = []
  #kidCache  = null
  #chain
  #checkpointEvery
  #institutionKid
  #sealed

  /** { seq, hash } of the last entry, or null for an empty log. Loaded once. */
  #tail = null
  /** Sealed logs only: entries since the last seal, which is what seal() signs. */
  #pending = []
  #ready = null
  /**
   * Writes run one at a time. Two appends in flight together would both read
   * the same tail and mint the same seq, which forks the chain at the point it
   * is supposed to be strongest.
   */
  #queue = Promise.resolve()

  constructor({ keypair, chain, checkpointEvery = 100, institutionKid, sealed = false } = {}) {
    if (!keypair?.secretKey || !keypair?.publicKey) {
      throw new KxcoPqAuditError('keypair with secretKey and publicKey is required')
    }
    this.#keypair         = keypair
    this.#chain           = chain           ?? null
    this.#checkpointEvery = checkpointEvery
    this.#institutionKid  = institutionKid  ?? null
    this.#sealed          = Boolean(sealed)
  }

  /** True when this log signs once per sealed run rather than once per entry. */
  get sealed() { return this.#sealed }

  /** The kid of the key this log signs with. Derived once; it cannot change. */
  #signingKid() {
    this.#kidCache ??= kidOf(this.#keypair.publicKey)
    return this.#kidCache
  }

  /**
   * The kid a verifier needs for the records this log is writing. Publishing it
   * alongside the log means a reader does not have to derive it from a key they
   * may not have yet.
   */
  get signingKid() { return this.#signingKid() }

  /**
   * One pass over whatever is already stored, to find the tail and, on a sealed
   * log, the entries the next seal will cover. Everything after this is O(1).
   */
  #load() {
    if (this.#ready) return this.#ready
    this.#ready = (async () => {
      const seals = await this._seals()
      const sealedThrough = seals.length === 0 ? -1 : seals[seals.length - 1].toSeq
      let last = null
      const pending = []
      for await (const entry of this._iterate()) {
        last = entry
        if (this.#sealed && entry.seq > sealedThrough) pending.push(entry)
      }
      this.#tail    = last === null ? null : { seq: last.seq, hash: hashEntry(last) }
      this.#pending = pending
    })()
    return this.#ready
  }

  /** Run a write with no other write in flight. A failure must not poison the queue. */
  #serial(fn) {
    const run = this.#queue.then(fn, fn)
    this.#queue = run.then(() => {}, () => {})
    return run
  }

  async append(operation, metadata = {}) {
    // Validate before queueing, so a bad call fails now rather than behind
    // however much work is already in flight.
    if (typeof operation !== 'string' || !operation) {
      throw new KxcoPqAuditError('operation must be a non-empty string')
    }
    return this.#serial(() => this.#appendOne(operation, metadata))
  }

  async #appendOne(operation, metadata) {
    await this.#load()

    const seq  = this.#tail === null ? 0 : this.#tail.seq + 1
    const prev = this.#tail === null ? null : this.#tail.hash
    const ts   = new Date().toISOString()

    // A sealed log chains every entry and signs none of them. The signature that
    // binds the run to the key is produced once, by seal(), because signing every
    // entry costs ~2ms and ~4.4KB and does not survive agent-scale volume.
    const entry = { seq, timestamp: ts, operation, metadata, prevHash: prev }
    if (!this.#sealed) {
      const msg = signingBytes(seq, ts, operation, metadata, prev)
      entry.signature = b64url(Buffer.from(mlDsa.sign(new Uint8Array(this.#keypair.secretKey), msg), 'hex'))
      // Which key signed this entry, so a log that outlives a rotation can say
      // so per entry rather than forcing one key across the whole file.
      entry.kid = this.#signingKid()
    }

    await this._store(entry)
    this.#tail = { seq, hash: hashEntry(entry) }
    if (this.#sealed) this.#pending.push(entry)

    // A sealed log anchors when it seals, not every N entries.
    const entryCount = seq + 1
    if (!this.#sealed && this.#chain && entryCount % this.#checkpointEvery === 0) {
      const rootHash = Buffer.from(sha256(enc.encode(JSON.stringify(entry)))).toString('hex')
      this.#chain.anchorAuditRoot({ rootHash, entryCount }).catch((err) => {
        console.warn(`[kxco-pq-audit] chain checkpoint failed (entry ${entryCount}): ${err.message}`)
      })
    }

    return entry
  }

  /**
   * Sign every entry written since the last seal, as one run.
   *
   * Returns the seal, or null when there is nothing unsealed. Safe to call
   * repeatedly. Entries appended after a seal are chained but carry no
   * signature until the next one, which is the honest cost of not signing
   * inline: verify() always reports how many are in that window.
   */
  async seal() {
    if (!this.#sealed) throw new KxcoPqAuditError('seal() requires sealed: true')
    // Sealing shares the write queue with append, so a run can never be sealed
    // half way through an entry being written into it.
    return this.#serial(() => this.#sealPending())
  }

  async #sealPending() {
    await this.#load()
    if (this.#pending.length === 0) return null

    const seals = await this._seals()
    const last  = seals.length === 0 ? null : seals[seals.length - 1]
    const run   = this.#pending

    const prevRoot  = last === null ? GENESIS_ROOT : last.rootHash
    const rootHash  = rootOf(prevRoot, run.map(hashEntry))
    const fromSeq   = run[0].seq
    const toSeq     = run[run.length - 1].seq
    const timestamp = new Date().toISOString()
    const msg       = sealBytes(fromSeq, toSeq, prevRoot, rootHash, timestamp)
    const signature = b64url(Buffer.from(mlDsa.sign(new Uint8Array(this.#keypair.secretKey), msg), 'hex'))

    const seal = {
      fromSeq,
      toSeq,
      entryCount: run.length,
      prevRoot,
      rootHash,
      timestamp,
      signature,
      institutionKid: this.#institutionKid,
      // The signing key, distinct from institutionKid, which names the
      // institution rather than the key that produced this signature.
      kid: this.#signingKid(),
    }
    await this._storeSeal(seal)
    this.#pending = []

    if (this.#chain) {
      this.#chain.anchorAuditRoot({ rootHash, entryCount: toSeq + 1 }).catch((err) => {
        console.warn(`[kxco-pq-audit] chain checkpoint failed (seal ${fromSeq}-${toSeq}): ${err.message}`)
      })
    }

    return seal
  }

  /** Every seal this log holds, oldest first. */
  async seals() {
    return this._seals()
  }

  /** Entries appended since the last seal. Sealed logs only. */
  async unsealedCount() {
    if (!this.#sealed) return 0
    await this.#load()
    return this.#pending.length
  }

  /**
   * Replay the log from entry 0. Streams, so memory is bounded by one entry and
   * the seal list rather than by the log.
   */
  async verify(publicKey) {
    const candidates = candidatesFrom(publicKey)
    const usedKids   = new Set()

    const seals = this.#sealed ? await this._seals() : []
    let sealIndex    = 0
    let expectedFrom = 0
    let prevRoot     = GENESIS_ROOT
    let runHashes    = []

    let count    = 0
    let prevHash = null
    let expectedSeq = 0

    for await (const entry of this._iterate()) {
      if (entry.seq !== expectedSeq) {
        return { valid: false, error: `entry ${count}: expected seq ${expectedSeq}, got ${entry.seq}` }
      }
      if (entry.prevHash !== prevHash) {
        return count === 0
          ? { valid: false, error: 'entry 0: prevHash must be null' }
          : { valid: false, error: `entry ${count}: prevHash mismatch` }
      }

      if (!this.#sealed) {
        const msg = signingBytes(entry.seq, entry.timestamp, entry.operation, entry.metadata, entry.prevHash)
        const res = verifySignature(candidates, entry.kid, msg, entry.signature, `entry ${count}`)
        if (res.error) return { valid: false, error: res.error }
        usedKids.add(res.kid)
      } else if (sealIndex < seals.length) {
        const s = seals[sealIndex]
        if (s.fromSeq !== expectedFrom) {
          return { valid: false, error: `seal ${sealIndex}: expected fromSeq ${expectedFrom}, got ${s.fromSeq}` }
        }
        if (s.prevRoot !== prevRoot) {
          return { valid: false, error: `seal ${sealIndex}: prevRoot does not chain to the seal before it` }
        }
        if (entry.seq >= s.fromSeq) runHashes.push(hashEntry(entry))
        if (entry.seq === s.toSeq) {
          const bad = this.#closeSeal(s, sealIndex, prevRoot, runHashes, candidates, usedKids)
          if (bad) return bad
          prevRoot     = s.rootHash
          expectedFrom = s.toSeq + 1
          runHashes    = []
          sealIndex++
        }
      }

      prevHash = hashEntry(entry)
      expectedSeq = entry.seq + 1
      count++
    }

    if (!this.#sealed) return { valid: true, count, kids: [...usedKids] }

    if (sealIndex < seals.length) {
      const s = seals[sealIndex]
      return { valid: false, error: `seal ${sealIndex}: covers seq ${s.toSeq}, log ends at ${count - 1}` }
    }

    // Never let an unsealed tail read as proven. sealedThrough is where the
    // signed record stops; unsealed entries are chained and nothing more.
    return {
      valid: true,
      count,
      sealedThrough: expectedFrom - 1,
      unsealed: count - expectedFrom,
      kids: [...usedKids],
    }
  }

  #closeSeal(s, index, prevRoot, runHashes, candidates, usedKids) {
    if (rootOf(prevRoot, runHashes) !== s.rootHash) {
      return { valid: false, error: `seal ${index}: entries do not reproduce rootHash` }
    }
    const msg = sealBytes(s.fromSeq, s.toSeq, s.prevRoot, s.rootHash, s.timestamp)
    const res = verifySignature(candidates, s.kid, msg, s.signature, `seal ${index}`)
    if (res.error) return { valid: false, error: res.error }
    usedKids.add(res.kid)
    return null
  }

  /**
   * Every entry as an array. Holds the whole log in memory by definition; on a
   * large log prefer `stream()`.
   */
  async export() {
    const out = []
    for await (const entry of this._iterate()) out.push(entry)
    return out
  }

  /** Every entry, in seq order, one at a time. */
  stream() {
    return this._iterate()
  }

  // --- storage hooks; a backend overrides these ---

  async _entries() { return [...this.#entries] }
  async _store(entry) { this.#entries.push(entry) }
  async _seals() { return [...this.#sealsList] }
  async _storeSeal(seal) { this.#sealsList.push(seal) }

  /**
   * Entries in seq order. The default reads them all through `_entries()`, so a
   * backend that only overrides `_entries()` still works; one that can stream
   * should override this instead.
   */
  async *_iterate() {
    for (const entry of await this._entries()) yield entry
  }
}
