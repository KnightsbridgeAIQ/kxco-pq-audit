// Property-based tests with fast-check.
//
// audit.test.js checks the log against a handful of hand-built cases: one
// edited field, one removed entry, one rotation. These ask the general
// question: for ANY sequence of operations and metadata, does the log verify,
// and does ANY edit, gap or reorder fail verification and name the entry where
// the record breaks? The same for sealed logs, and for a file that outlived a
// key rotation across several keys. fast-check generates the inputs and, when a
// property breaks, shrinks the failing case to the smallest one that still
// breaks it.
//
// No chain client is passed, so nothing is anchored and nothing leaves the
// machine. FileAuditLog works in a temporary directory removed afterwards.
//
// Runs on whichever backend kxco-post-quantum reports.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { AuditLog, FileAuditLog, KxcoPqAuditError } from '../src/index.js'

const dir = mkdtempSync(join(tmpdir(), 'kxco-audit-property-'))
after(() => rmSync(dir, { recursive: true, force: true }))
let files = 0
const freshPath = () => join(dir, `log-${++files}.ndjson`)

// A pool of signing keys, so a rotation can pass through several of them.
const keys = [0, 1, 2, 3].map(() => mlDsa.ml_dsa65.keygen())
const kidOf = (k) => fingerprint(k.publicKey)
const [key, stranger] = keys

const operation = fc.oneof(
  fc.string({ minLength: 1, maxLength: 30 }),
  fc.string({ unit: 'grapheme', minLength: 1, maxLength: 12 }),
)
const metadata = fc.dictionary(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 4 })
const records = (min, max) => fc.array(fc.tuple(operation, metadata), { minLength: min, maxLength: max })

async function build(recs, opts = {}) {
  const log = new AuditLog({ keypair: key, ...opts })
  const appended = []
  for (const [op, meta] of recs) appended.push(await log.append(op, meta))
  return { log, appended }
}

// Reads a log back through the backend hook the package documents, so a test
// can hand verify() a tampered copy of the entries.
function replay(log, entries) {
  log._entries = async () => entries
  return log
}

const copy = (entries) => entries.map((e) => JSON.parse(JSON.stringify(e)))

// One change to one field of one entry, always to a different value.
const fieldEdit = fc.oneof(
  fc.string({ maxLength: 8 }).map((s) => ['operation', (e) => e.operation + 'x' + s]),
  fc.jsonValue({ maxDepth: 1 }).map((v) => ['metadata', (e) => ({ ...e.metadata, k_tampered: v })]),
  fc.integer({ min: 1, max: 1e6 }).map((ms) => ['timestamp', (e) => new Date(Date.parse(e.timestamp) + ms).toISOString()]),
  fc.integer({ min: 1, max: 1000 }).map((d) => ['seq', (e) => e.seq + d]),
  fc.stringMatching(/^[A-Za-z0-9_-]{43}$/).map((h) => ['prevHash', () => h]),
  fc.nat().map((at) => ['signature', (e) => {
    const b = Buffer.from(e.signature, 'base64url')
    b[at % b.length] ^= 0x01
    return b.toString('base64url')
  }]),
  fc.stringMatching(/^[0-9a-f]{16}$/).map((k) => ['kid', () => k]),
)

// What an edited file line can hold instead of a record: text that is not
// JSON, or JSON that is not an object (null, a number, a string, a boolean or
// an array). Single lines, since the files are one record per line.
const notJson = fc.string({ unit: 'binary', minLength: 1, maxLength: 80 }).filter((s) => {
  if (/[\r\n]/.test(s)) return false
  try { JSON.parse(s); return false } catch { return true }
})
const notObject = fc.jsonValue({ maxDepth: 2 })
  .filter((v) => v === null || typeof v !== 'object' || Array.isArray(v))
  .map((v) => JSON.stringify(v))

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('any sequence of appends verifies, chained in order, and only under the key that signed it', async () => {
  await fc.assert(fc.asyncProperty(records(0, 5), async (recs) => {
    const { log, appended } = await build(recs)
    const r = await log.verify(key.publicKey)
    const exported = await log.export()
    const wrong = await log.verify(stranger.publicKey)
    return r.valid === true &&
      r.count === recs.length &&
      JSON.stringify(r.kids) === JSON.stringify(recs.length ? [kidOf(key)] : []) &&
      exported.length === recs.length &&
      exported.every((e, i) =>
        e.seq === i &&
        e.operation === recs[i][0] &&
        JSON.stringify(e.metadata) === JSON.stringify(recs[i][1]) &&
        e.kid === kidOf(key) &&
        (i === 0 ? e.prevHash === null : typeof e.prevHash === 'string') &&
        JSON.stringify(e) === JSON.stringify(appended[i])) &&
      (recs.length === 0 ? wrong.valid === true : wrong.valid === false && /^entry 0: signed by kid /.test(wrong.error))
  }), { numRuns: 20 })
})

// Verified against the checkpoint an earlier verify() returned, so a gap can be
// anywhere, the last entry included: nothing follows the last entry to break
// its chain, and the checkpoint is what records that it was there.
test('any edit, gap or reorder in a signed log fails verification against a checkpoint and names the entry', async () => {
  const mutation = fc.oneof(
    fc.tuple(fc.constant('edit'), fc.nat(), fieldEdit),
    fc.tuple(fc.constant('gap'), fc.nat()),
    fc.tuple(fc.constant('swap'), fc.nat(), fc.nat()),
  )
  await fc.assert(fc.asyncProperty(records(2, 5), mutation, async (recs, m) => {
    const { log } = await build(recs)
    const checkpoint = await log.verify(key.publicKey)
    const entries = copy(await log.export())
    const n = entries.length
    let expected
    if (m[0] === 'edit') {
      const i = m[1] % n
      const [field, change] = m[2]
      entries[i] = { ...entries[i], [field]: change(entries[i]) }
      expected = new RegExp(`^entry ${i}: `)
    } else if (m[0] === 'gap') {
      const i = m[1] % n
      entries.splice(i, 1)
      expected = i === n - 1
        ? new RegExp(`^checkpoint: covers seq ${i}, log ends at ${i - 1}$`)
        : new RegExp(`^entry ${i}: expected seq ${i}, got ${i + 1}$`)
    } else {
      const i = m[1] % n
      const j = m[2] % n
      fc.pre(i !== j)
      const [lo, hi] = i < j ? [i, j] : [j, i];
      [entries[lo], entries[hi]] = [entries[hi], entries[lo]]
      expected = new RegExp(`^entry ${lo}: expected seq ${lo}, got ${hi}$`)
    }
    const r = await replay(log, entries).verify(key.publicKey, { checkpoint })
    return checkpoint.valid === true && r.valid === false && expected.test(r.error)
  }), { numRuns: 25 })
})

test('sealed: any run of appends and seals verifies, and any edit, removal or reorder of a sealed entry fails and names where', async () => {
  // Each step appends some entries, then seals them.
  const steps = fc.array(fc.array(fc.tuple(operation, metadata), { minLength: 1, maxLength: 6 }), { minLength: 1, maxLength: 3 })
  const mutation = fc.oneof(
    fc.tuple(fc.constant('edit'), fc.nat(), fc.constantFrom('operation', 'metadata', 'timestamp')),
    fc.tuple(fc.constant('remove'), fc.nat()),
    fc.tuple(fc.constant('swap'), fc.nat(), fc.nat()),
  )
  await fc.assert(fc.asyncProperty(steps, records(0, 3), mutation, async (runs, tail, m) => {
    const log = new AuditLog({ keypair: key, sealed: true })
    const boundaries = []
    let n = 0
    for (const run of runs) {
      for (const [op, meta] of run) await log.append(op, meta)
      n += run.length
      const seal = await log.seal()
      boundaries.push(seal.toSeq)
    }
    for (const [op, meta] of tail) await log.append(op, meta)

    // An unsealed tail is reported as such, never counted as proven.
    const ok = await log.verify(key.publicKey)
    const unsealed = await log.unsealedCount()
    const valid = ok.valid === true &&
      ok.count === n + tail.length &&
      ok.sealedThrough === n - 1 &&
      ok.unsealed === tail.length &&
      unsealed === tail.length &&
      JSON.stringify(ok.kids) === JSON.stringify([kidOf(key)])

    // Seal the tail too, so every entry the mutation can touch is sealed.
    const last = await log.seal()
    if ((last === null) !== (tail.length === 0)) return false
    if (last !== null) boundaries.push(last.toSeq)
    const sealedCount = n + tail.length

    const entries = copy(await log.export())
    let expected
    if (m[0] === 'edit') {
      const i = m[1] % sealedCount
      const field = m[2]
      entries[i] = {
        ...entries[i],
        [field]: field === 'metadata' ? { ...entries[i].metadata, k_tampered: 1 }
          : field === 'timestamp' ? new Date(Date.parse(entries[i].timestamp) + 1).toISOString()
            : entries[i].operation + 'x',
      }
      const k = boundaries.indexOf(i)
      expected = k >= 0 ? `seal ${k}: entries do not reproduce rootHash` : `entry ${i + 1}: prevHash mismatch`
    } else if (m[0] === 'remove') {
      const i = m[1] % sealedCount
      entries.splice(i, 1)
      expected = i === sealedCount - 1
        ? `seal ${boundaries.length - 1}: covers seq ${i}, log ends at ${i - 1}`
        : `entry ${i}: expected seq ${i}, got ${i + 1}`
    } else {
      const i = m[1] % sealedCount
      const j = m[2] % sealedCount
      fc.pre(i !== j)
      const [lo, hi] = i < j ? [i, j] : [j, i];
      [entries[lo], entries[hi]] = [entries[hi], entries[lo]]
      expected = `entry ${lo}: expected seq ${lo}, got ${hi}`
    }
    const r = await replay(log, entries).verify(key.publicKey)
    return valid && r.valid === false && r.error === expected
  }), { numRuns: 30 })
})

test('rotation: a file written under several keys in turn verifies with all of them in any order, and names the first entry of any key left out', async () => {
  const plan = fc.shuffledSubarray([0, 1, 2, 3], { minLength: 2, maxLength: 4 }).chain((order) => fc.record({
    order: fc.constant(order),
    lengths: fc.array(fc.integer({ min: 1, max: 2 }), { minLength: order.length, maxLength: order.length }),
    supplied: fc.shuffledSubarray([0, 1, 2, 3], { minLength: 4, maxLength: 4 }),
    omit: fc.nat({ max: order.length - 1 }),
    op: operation,
    meta: metadata,
  }))
  await fc.assert(fc.asyncProperty(plan, async ({ order, lengths, supplied, omit, op, meta }) => {
    const path = freshPath()
    const appended = []
    const firstEntryOf = []
    for (let k = 0; k < order.length; k++) {
      // The rotation: the same file, opened by a new writer holding the next key.
      const writer = new FileAuditLog({ keypair: keys[order[k]], path })
      firstEntryOf.push(appended.length)
      for (let e = 0; e < lengths[k]; e++) appended.push(await writer.append(op, meta))
      await writer.close()
    }

    const reader = new FileAuditLog({ keypair: key, path })
    const all = await reader.verify(supplied.map((i) => keys[i].publicKey))
    const missingKey = keys[order[omit]]
    const partial = await reader.verify(keys.filter((k) => k !== missingKey).map((k) => k.publicKey))
    const exported = await reader.export()
    await reader.close()

    return all.valid === true &&
      all.count === appended.length &&
      JSON.stringify(all.kids) === JSON.stringify(order.map((i) => kidOf(keys[i]))) &&
      JSON.stringify(exported) === JSON.stringify(appended) &&
      partial.valid === false &&
      partial.error === `entry ${firstEntryOf[omit]}: signed by kid ${kidOf(missingKey)}, which was not among the 3 key(s) supplied`
  }), { numRuns: 20 })
})

test('FileAuditLog: a line that is not a JSON object, anywhere in the file, is refused with the package error naming that line', async () => {
  const path = freshPath()
  const writer = new FileAuditLog({ keypair: key, path, sealed: true })
  for (let i = 0; i < 5; i++) await writer.append('op', { i })
  await writer.seal()
  await writer.close()
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean)
  const seals = readFileSync(path + '.seals', 'utf8')

  const junk = fc.oneof(
    notJson.map((text) => [text, 'is not valid JSON']),
    notObject.map((text) => [text, 'is JSON but not an audit entry']),
  )
  await fc.assert(fc.asyncProperty(fc.nat({ max: lines.length - 1 }), junk, async (at, [text, says]) => {
    const edited = freshPath()
    writeFileSync(edited, lines.map((l, i) => (i === at ? text : l)).join('\n') + '\n')
    writeFileSync(edited + '.seals', seals)
    const reader = new FileAuditLog({ keypair: key, path: edited, sealed: true })
    try {
      await reader.verify(key.publicKey)
      return false
    } catch (err) {
      return err instanceof KxcoPqAuditError && err.message.includes(`line ${at + 1} ${says}`)
    }
  }), { numRuns: 50 })
})

test('FileAuditLog: a seals line that is not a JSON object, anywhere in the seals file, is refused with the package error naming that line', async () => {
  const path = freshPath()
  const writer = new FileAuditLog({ keypair: key, path, sealed: true })
  for (let i = 0; i < 4; i++) {
    await writer.append('op', { i })
    await writer.seal()
  }
  await writer.close()
  const entries = readFileSync(path, 'utf8')
  const seals = readFileSync(path + '.seals', 'utf8').split('\n').filter(Boolean)

  // A seal cut short, as an interrupted write leaves one.
  const torn = fc.tuple(fc.nat({ max: seals.length - 1 }), fc.nat())
    .map(([k, cut]) => seals[k].slice(0, 1 + (cut % (seals[k].length - 1))))
  const junk = fc.oneof(
    fc.oneof(notJson, torn).map((text) => [text, 'is not valid JSON']),
    notObject.map((text) => [text, 'is JSON but not a seal']),
  )
  await fc.assert(fc.asyncProperty(fc.nat({ max: seals.length - 1 }), junk, async (at, [text, says]) => {
    const edited = freshPath()
    writeFileSync(edited, entries)
    writeFileSync(edited + '.seals', seals.map((l, i) => (i === at ? text : l)).join('\n') + '\n')
    const reader = new FileAuditLog({ keypair: key, path: edited, sealed: true })
    try {
      await reader.verify(key.publicKey)
      return false
    } catch (err) {
      return err instanceof KxcoPqAuditError && err.message.includes(`.seals: line ${at + 1} ${says}`)
    }
  }), { numRuns: 50 })
})
