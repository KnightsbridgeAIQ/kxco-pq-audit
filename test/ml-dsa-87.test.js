// ML-DSA-87 logs: the signing key decides the set, an ML-DSA-87 record carries
// its algorithm inside the signed bytes, the verifier takes the algorithm from
// the key it is given, and logs written before any of this verify unchanged.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { AuditLog, FileAuditLog, KxcoPqAuditError } from '../src/index.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-65.json', import.meta.url), 'utf-8'))

let k65, k87
before(() => {
  k65 = mlDsa.ml_dsa65.keygen()
  k87 = mlDsa87.ml_dsa87.keygen()
})

// A log whose stored records are whatever the test hands it.
function holding(entries, seals = [], opts = {}) {
  const log = new AuditLog({ keypair: k65, ...opts })
  log._entries = async () => entries.map((e) => ({ ...e }))
  log._seals = async () => seals.map((s) => ({ ...s }))
  return log
}

test('an ML-DSA-87 log signs every entry as ML-DSA-87 and records it', async () => {
  const log = new AuditLog({ keypair: k87 })
  assert.equal(log.signingAlg, 'ML-DSA-87')
  const e = await log.append('op', { n: 1 })
  assert.equal(e.alg, 'ML-DSA-87')
  assert.equal(e.kid, fingerprint(k87.publicKey))
  assert.equal(Buffer.from(e.signature, 'base64url').length, 4627)
  await log.append('op', { n: 2 })
  const r = await log.verify(k87.publicKey)
  assert.equal(r.valid, true)
  assert.equal(r.count, 2)
  assert.deepEqual(r.kids, [fingerprint(k87.publicKey)])
})

test('an ML-DSA-65 log keeps the v1 entry shape, with no alg', async () => {
  const log = new AuditLog({ keypair: k65 })
  assert.equal(log.signingAlg, 'ML-DSA-65')
  const e = await log.append('op', {})
  assert.deepEqual(Object.keys(e), ['seq', 'timestamp', 'operation', 'metadata', 'prevHash', 'signature', 'kid'])
  assert.equal((await log.verify(k65.publicKey)).valid, true)
})

test('a sealed ML-DSA-87 log seals as ML-DSA-87', async () => {
  const log = new AuditLog({ keypair: k87, sealed: true })
  await log.append('a', {}); await log.append('b', {})
  const s = await log.seal()
  assert.equal(s.alg, 'ML-DSA-87')
  assert.equal(Buffer.from(s.signature, 'base64url').length, 4627)
  const r = await log.verify(k87.publicKey)
  assert.equal(r.valid, true)
  assert.equal(r.sealedThrough, 1)
  assert.deepEqual(await log.verify(k65.publicKey), { valid: false, error: `seal 0: signed by kid ${s.kid}, which was not among the 1 key(s) supplied` })
})

test('the verifier takes the algorithm from the key: a record stating the other set is refused', async () => {
  const log = new AuditLog({ keypair: k87 })
  const e = await log.append('op', {})
  // Restate the entry as ML-DSA-65 under the same kid: the key says ML-DSA-87.
  const restated = holding([{ ...e, alg: 'ML-DSA-65' }])
  assert.deepEqual(await restated.verify(k87.publicKey),
    { valid: false, error: `entry 0: signed as ML-DSA-65, but kid ${e.kid} is an ML-DSA-87 key` })
  // Stripped of alg, it reads as v1, which means ML-DSA-65: refused the same way.
  const { alg, ...stripped } = e
  assert.equal(alg, 'ML-DSA-87')
  assert.deepEqual(await holding([stripped]).verify(k87.publicKey),
    { valid: false, error: `entry 0: signed as ML-DSA-65, but kid ${e.kid} is an ML-DSA-87 key` })
})

test('a log that rotated from ML-DSA-65 to ML-DSA-87 verifies with both keys, each record by its own', async () => {
  const before65 = new AuditLog({ keypair: k65 })
  await before65.append('old', {})
  const entries = await before65.export()
  // The ML-DSA-87 key carries on from the same tail.
  const after87 = new AuditLog({ keypair: k87 })
  after87._entries = async () => entries
  after87._store = async (e) => { entries.push(e) }
  await after87.append('new', {})
  const log = holding(entries)
  const r = await log.verify([k65.publicKey, k87.publicKey])
  assert.equal(r.valid, true)
  assert.deepEqual(r.kids, [fingerprint(k65.publicKey), fingerprint(k87.publicKey)])
  assert.equal(entries[0].alg, undefined)
  assert.equal(entries[1].alg, 'ML-DSA-87')
})

test('a record without a kid is tried only against keys of the set it states', async () => {
  const log = new AuditLog({ keypair: k87 })
  const e = await log.append('op', {})
  const { kid, ...noKid } = e
  assert.equal(typeof kid, 'string')
  assert.equal((await holding([noKid]).verify([k65.publicKey, k87.publicKey])).valid, true)
  assert.deepEqual(await holding([noKid]).verify([k65.publicKey]), { valid: false, error: 'entry 0: signature invalid' })
})

test('a signing key of neither set is refused when it would sign', async () => {
  const log = new AuditLog({ keypair: { publicKey: new Uint8Array(10), secretKey: new Uint8Array(10) } })
  await assert.rejects(log.append('op', {}), KxcoPqAuditError)
})

test('FileAuditLog keeps the alg through a write and a reopen', async () => {
  const path = join(tmpdir(), `kxco-audit-87-${process.pid}-${Date.now()}.jsonl`)
  try {
    const log = new FileAuditLog({ keypair: k87, path })
    await log.append('a', {}); await log.append('b', {})
    const reopened = new FileAuditLog({ keypair: k87, path })
    const [first] = await reopened.export()
    assert.equal(first.alg, 'ML-DSA-87')
    assert.equal((await reopened.verify(k87.publicKey)).valid, true)
  } finally {
    try { unlinkSync(path) } catch {}
  }
})

// The bytes themselves, from the published layout, so another implementation
// can reproduce them: v1.1 replaces the first line and puts the algorithm on
// the second; the rest is the v1 message.
test('wire format: ML-DSA-87 entries and seals are signed over the v1.1 bytes', async () => {
  const log = new AuditLog({ keypair: k87 })
  const e = await log.append('op', { n: 1 })
  const tail = `${e.seq}\n${e.timestamp}\n${e.operation}\nnull\n${JSON.stringify(e.metadata)}`
  const sig = Buffer.from(e.signature, 'base64url').toString('hex')
  const bytes = (s) => new TextEncoder().encode(s)
  assert.equal(mlDsa87.verify(k87.publicKey, bytes(`kxco-audit-v1.1\nML-DSA-87\n${tail}`), sig), true)
  assert.equal(mlDsa87.verify(k87.publicKey, bytes(`kxco-audit-v1\n${tail}`), sig), false)

  const sealed = new AuditLog({ keypair: k87, sealed: true })
  await sealed.append('a', {})
  const s = await sealed.seal()
  const sealTail = `${s.fromSeq}\n${s.toSeq}\n${s.prevRoot}\n${s.rootHash}\n${s.timestamp}`
  const sealSig = Buffer.from(s.signature, 'base64url').toString('hex')
  assert.equal(mlDsa87.verify(k87.publicKey, bytes(`kxco-audit-seal-v1.1\nML-DSA-87\n${sealTail}`), sealSig), true)
  assert.equal(mlDsa87.verify(k87.publicKey, bytes(`kxco-audit-seal-v1\n${sealTail}`), sealSig), false)
})

test('logs written by 1.4.5, before ML-DSA-87, still verify', async () => {
  const pub = Buffer.from(LEGACY.publicKey, 'hex')
  assert.equal(LEGACY.classic.some((e) => 'alg' in e), false)
  const classic = await holding(LEGACY.classic).verify(pub)
  assert.equal(classic.valid, true)
  assert.equal(classic.count, 3)

  const sealed = await holding(LEGACY.sealedEntries, LEGACY.seals, { sealed: true }).verify(pub)
  assert.equal(sealed.valid, true)
  assert.equal(sealed.sealedThrough, 2)
  assert.equal(sealed.unsealed, 0)
})
