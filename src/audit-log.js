import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { sha256 } from '@noble/hashes/sha2.js'
import { KxcoPqAuditError } from './errors.js'

/**
 * The ML-DSA parameter sets a log can be signed with. The KEY decides which:
 * a key's length names its set, on the writing side and the verifying side.
 *
 * An ML-DSA-65 record is signed over the v1 bytes, exactly as before, and
 * carries no `alg`, so a log written by this version still verifies under
 * 1.4.x and earlier. An ML-DSA-87 record carries `alg: 'ML-DSA-87'` and is
 * signed over v1.1 bytes, whose first line differs from v1 and whose second
 * line is the algorithm, so the algorithm is inside the signed bytes. A record
 * whose `alg` names neither set is read as v1, which means ML-DSA-65: that is
 * how every record made before the field existed reads.
 */
const SETS = Object.freeze({
  'ML-DSA-65': Object.freeze({ module: mlDsa,   publicKeyBytes: 1952, secretKeyBytes: 4032 }),
  'ML-DSA-87': Object.freeze({ module: mlDsa87, publicKeyBytes: 2592, secretKeyBytes: 4896 }),
})
const DEFAULT_ALG = 'ML-DSA-65'

function algForKey(key, field) {
  for (const [name, set] of Object.entries(SETS)) if (key?.length === set[field]) return name
  return null
}

const statedAlg = (value) => (Object.hasOwn(SETS, value) ? value : null)

function versionLine(tag, alg) {
  return alg === null ? `${tag}-v1` : `${tag}-v1.1\n${alg}`
}

const enc = new TextEncoder()

function b64url(bytes)  { return Buffer.from(bytes).toString('base64url') }
function fromB64url(s)  { return new Uint8Array(Buffer.from(s, 'base64url')) }

function hashEntry(entry) {
  return b64url(sha256(enc.encode(JSON.stringify(entry))))
}

function signingBytes(seq, timestamp, operation, metadata, prevHash, alg = null) {
  return enc.encode(
    `${versionLine('kxco-audit', alg)}\n${seq}\n${timestamp}\n${operation}\n${prevHash ?? 'null'}\n${JSON.stringify(metadata)}`
  )
}

function sealBytes(fromSeq, toSeq, prevRoot, rootHash, timestamp, alg = null) {
  return enc.encode(
    `${versionLine('kxco-audit-seal', alg)}\n${fromSeq}\n${toSeq}\n${prevRoot}\n${rootHash}\n${timestamp}`
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
    return { kid: kidOf(bytes), publicKey: bytes, alg: algForKey(bytes, 'publicKeyBytes') }
  })
}

/**
 * Normalise a checkpoint: what a verifier kept from an earlier look at the log.
 *
 * `count` is how many entries the log held and `tip` the hash of the last of
 * them, so any earlier verify() result is a checkpoint as it stands. Either may
 * be given alone. Checked strictly, because a checkpoint that names nothing
 * would check nothing and read as a pass.
 */
function checkpointFrom(checkpoint) {
  if (checkpoint === undefined) return null
  const count = checkpoint?.count
  const tip   = checkpoint?.tip ?? undefined
  if (count !== undefined && !(Number.isSafeInteger(count) && count >= 0)) {
    throw new KxcoPqAuditError('verify: checkpoint.count must be a whole number of entries')
  }
  if (tip !== undefined && typeof tip !== 'string') {
    throw new KxcoPqAuditError('verify: checkpoint.tip must be the hash string an earlier verify() returned')
  }
  if (count === undefined && tip === undefined) {
    throw new KxcoPqAuditError('verify: a checkpoint needs a count, a tip or both')
  }
  if (count === 0 && tip !== undefined) {
    throw new KxcoPqAuditError('verify: a checkpoint with a tip covers at least one entry')
  }
  return { count, tip }
}

/**
 * Check one record's signature. `messageFor(alg)` builds the signed bytes for
 * the algorithm the record states (null for a v1 record).
 *
 * The key decides the algorithm. A record stating the other set from the key
 * its kid names is refused rather than tried, and a record with no kid is
 * tried only against keys of the set it states.
 */
function verifySignature(candidates, recordKid, recordAlg, messageFor, signatureB64, label) {
  const sigHex = () => Buffer.from(fromB64url(signatureB64)).toString('hex')
  const stated = statedAlg(recordAlg)
  const alg    = stated ?? DEFAULT_ALG
  const msg    = messageFor(stated)
  const verifyWith = (c) => {
    if (c.alg !== alg) return false
    try { return SETS[alg].module.verify(c.publicKey, msg, sigHex()) } catch { return false }
  }

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
    if (match.alg !== null && match.alg !== alg) {
      return { error: `${label}: signed as ${alg}, but kid ${recordKid} is an ${match.alg} key` }
    }
    return verifyWith(match) ? { kid: match.kid } : { error: `${label}: signature invalid` }
  }

  // No kid: a log written before 1.4.0. Try each key of the stated set.
  for (const c of candidates) {
    if (verifyWith(c)) return { kid: c.kid }
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

  /** The set this log signs with, decided by its secret key. */
  #signingAlg() {
    const alg = algForKey(this.#keypair.secretKey, 'secretKeyBytes')
    if (alg === null) throw new KxcoPqAuditError('the signing key is neither ML-DSA-65 nor ML-DSA-87')
    return alg
  }

  /** Sign `bytesFor(stated)`; returns the base64url signature and the alg to record, if any. */
  #sign(bytesFor) {
    const alg    = this.#signingAlg()
    const stated = alg === DEFAULT_ALG ? null : alg
    const sig    = SETS[alg].module.sign(new Uint8Array(this.#keypair.secretKey), bytesFor(stated))
    return { signature: b64url(Buffer.from(sig, 'hex')), stated }
  }

  /** The parameter set this log signs with: 'ML-DSA-65' or 'ML-DSA-87'. */
  get signingAlg() { return this.#signingAlg() }

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
      const { signature, stated } = this.#sign((alg) => signingBytes(seq, ts, operation, metadata, prev, alg))
      entry.signature = signature
      // Which key signed this entry, so a log that outlives a rotation can say
      // so per entry rather than forcing one key across the whole file.
      entry.kid = this.#signingKid()
      // ML-DSA-87 only; inside the signed bytes. An ML-DSA-65 entry is v1.
      if (stated) entry.alg = stated
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
    const { signature, stated } = this.#sign((alg) => sealBytes(fromSeq, toSeq, prevRoot, rootHash, timestamp, alg))

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
      // ML-DSA-87 only; inside the signed bytes. An ML-DSA-65 seal is v1.
      ...(stated && { alg: stated }),
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
   *
   * The chain catches an entry removed from before the last, because the entry
   * after it stops linking. Nothing follows the last entry, so its removal is
   * caught against a checkpoint: the `{ count, tip }` an earlier verify()
   * returned. The log may have grown since, but the entry the checkpoint was
   * taken at must still be there, unchanged.
   */
  async verify(publicKey, { checkpoint } = {}) {
    const candidates = candidatesFrom(publicKey)
    const pin        = checkpointFrom(checkpoint)
    const usedKids   = new Set()
    let tipSeen      = false

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
        const msgFor = (alg) => signingBytes(entry.seq, entry.timestamp, entry.operation, entry.metadata, entry.prevHash, alg)
        const res = verifySignature(candidates, entry.kid, entry.alg, msgFor, entry.signature, `entry ${count}`)
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
      if (pin?.tip !== undefined) {
        if (pin.count === undefined) {
          tipSeen ||= prevHash === pin.tip
        } else if (count === pin.count - 1) {
          if (prevHash !== pin.tip) {
            return { valid: false, error: `checkpoint: entry ${count} does not match the checkpoint tip` }
          }
          tipSeen = true
        }
      }
      expectedSeq = entry.seq + 1
      count++
    }

    if (pin?.count !== undefined && count < pin.count) {
      return { valid: false, error: `checkpoint: covers seq ${pin.count - 1}, log ends at ${count - 1}` }
    }
    if (pin?.tip !== undefined && !tipSeen) {
      return { valid: false, error: 'checkpoint: no entry matches the checkpoint tip' }
    }

    // The hash of the last entry, which the next one will chain to. With
    // `count`, it is the checkpoint a later verify() can be held to.
    const tip = prevHash

    if (!this.#sealed) return { valid: true, count, kids: [...usedKids], tip }

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
      tip,
    }
  }

  #closeSeal(s, index, prevRoot, runHashes, candidates, usedKids) {
    if (rootOf(prevRoot, runHashes) !== s.rootHash) {
      return { valid: false, error: `seal ${index}: entries do not reproduce rootHash` }
    }
    const msgFor = (alg) => sealBytes(s.fromSeq, s.toSeq, s.prevRoot, s.rootHash, s.timestamp, alg)
    const res = verifySignature(candidates, s.kid, s.alg, msgFor, s.signature, `seal ${index}`)
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
