import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { unlinkSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mlDsa } from 'kxco-post-quantum'
import { AuditLog, FileAuditLog } from '../src/index.js'

const keypair = mlDsa.ml_dsa65.keygen()

describe('AuditLog (memory)', () => {
  test('first entry has seq 0 and null prevHash', async () => {
    const log = new AuditLog({ keypair })
    const entry = await log.append('keygen', { label: 'k1' })
    assert.equal(entry.seq, 0)
    assert.equal(entry.prevHash, null)
    assert.ok(entry.signature)
    assert.ok(entry.timestamp)
  })

  test('second entry has seq 1 and non-null prevHash', async () => {
    const log = new AuditLog({ keypair })
    await log.append('op1', {})
    const e2 = await log.append('op2', {})
    assert.equal(e2.seq, 1)
    assert.ok(e2.prevHash !== null)
  })

  test('verify passes on a valid 3-entry log', async () => {
    const log = new AuditLog({ keypair })
    await log.append('keygen', { label: 'k1' })
    await log.append('sign',   { label: 'k1', bytes: 24 })
    await log.append('verify', { kid: 'abc123' })
    const { valid, count } = await log.verify(keypair.publicKey)
    assert.equal(valid, true)
    assert.equal(count, 3)
  })

  test('verify returns count 0 on empty log', async () => {
    const log = new AuditLog({ keypair })
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.count, 0)
  })

  test('verify fails with wrong public key', async () => {
    const log = new AuditLog({ keypair })
    await log.append('keygen', { label: 'k1' })
    const other = mlDsa.ml_dsa65.keygen()
    const result = await log.verify(other.publicKey)
    assert.equal(result.valid, false)
    // Named rather than generic: the entry records which key signed it, so the
    // refusal can point at the key that is missing.
    assert.match(result.error, /entry 0: signed by kid [0-9a-f]{16}, which was not among/)
  })

  test('export returns entries in insertion order', async () => {
    const log = new AuditLog({ keypair })
    await log.append('a', {})
    await log.append('b', {})
    await log.append('c', {})
    const entries = await log.export()
    assert.deepEqual(entries.map(e => e.operation), ['a', 'b', 'c'])
  })

  test('empty operation string throws', async () => {
    const log = new AuditLog({ keypair })
    await assert.rejects(() => log.append(''), /non-empty/)
  })

  test('missing keypair throws', () => {
    assert.throws(() => new AuditLog({}), /keypair/)
  })
})

describe('AuditLog (sealed)', () => {
  const run = async (n = 5) => {
    const log = new AuditLog({ keypair, sealed: true })
    for (let i = 0; i < n; i++) await log.append('tool_call', { step: i })
    return log
  }

  test('entries carry no signature, and the run does', async () => {
    const log = await run(3)
    const entries = await log.export()
    assert.ok(entries.every(e => e.signature === undefined))
    assert.ok(entries.every(e => e.prevHash !== undefined))
    const seal = await log.seal()
    assert.equal(seal.fromSeq, 0)
    assert.equal(seal.toSeq, 2)
    assert.equal(seal.entryCount, 3)
    assert.ok(seal.signature)
  })

  test('a sealed run verifies', async () => {
    const log = await run(5)
    await log.seal()
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.count, 5)
    assert.equal(result.unsealed, 0)
    assert.equal(result.sealedThrough, 4)
  })

  test('an unsealed tail is reported, never counted as proven', async () => {
    const log = await run(5)
    await log.seal()
    await log.append('tool_call', { step: 5 })
    await log.append('tool_call', { step: 6 })
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.sealedThrough, 4)
    assert.equal(result.unsealed, 2)
  })

  test('seal() returns null when nothing is unsealed', async () => {
    const log = await run(3)
    assert.ok(await log.seal())
    assert.equal(await log.seal(), null)
  })

  test('successive seals chain to each other', async () => {
    const log = await run(3)
    const first = await log.seal()
    await log.append('tool_call', { step: 3 })
    const second = await log.seal()
    assert.equal(second.prevRoot, first.rootHash)
    assert.equal(second.fromSeq, 3)
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.unsealed, 0)
  })

  test('editing a sealed entry breaks the run', async () => {
    const log = await run(5)
    await log.seal()
    const entries = await log.export()
    entries[2].metadata.step = 99
    log._entries = async () => entries
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, false)
    assert.match(result.error, /prevHash mismatch|reproduce rootHash/)
  })

  test('removing a sealed entry breaks the run', async () => {
    const log = await run(5)
    await log.seal()
    const entries = (await log.export()).filter(e => e.seq !== 2)
    log._entries = async () => entries
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, false)
  })

  test('dropping a whole seal breaks the seal that follows it', async () => {
    const log = await run(3)
    await log.seal()
    await log.append('tool_call', { step: 3 })
    await log.seal()
    const seals = (await log.seals()).slice(1)
    log._seals = async () => seals
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, false)
    assert.match(result.error, /expected fromSeq 0/)
  })

  test('a seal signed by another key is refused', async () => {
    const log = await run(3)
    await log.seal()
    const other = mlDsa.ml_dsa65.keygen()
    const result = await log.verify(other.publicKey)
    assert.equal(result.valid, false)
    // The seal names the key that signed it, so the refusal can say the key was
    // never supplied rather than only that a signature did not check out. Both
    // are refusals; this one tells you which key to go and find.
    assert.match(result.error, /seal 0: signed by kid [0-9a-f]{16}, which was not among/)
  })

  test('seal() on a classic log throws rather than signing nothing', async () => {
    const log = new AuditLog({ keypair })
    await log.append('op', {})
    await assert.rejects(() => log.seal(), /requires sealed/)
  })

  test('a classic log is unchanged by the option existing', async () => {
    const log = new AuditLog({ keypair })
    const entry = await log.append('keygen', { label: 'k1' })
    assert.ok(entry.signature)
    const result = await log.verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.unsealed, undefined)
  })
})

describe('FileAuditLog', () => {
  const path = join(tmpdir(), `kxco-audit-test-${process.pid}.ndjson`)
  after(() => { try { unlinkSync(path) } catch { /* ok */ } })

  test('persists entries across instances', async () => {
    const log1 = new FileAuditLog({ keypair, path })
    await log1.append('keygen', { label: 'k1' })
    await log1.append('sign',   { label: 'k1' })

    await log1.close()

    const log2 = new FileAuditLog({ keypair, path })
    const entries = await log2.export()
    assert.equal(entries.length, 2)
    assert.equal(entries[0].operation, 'keygen')
    assert.equal(entries[1].operation, 'sign')
    await log2.close()
  })

  test('verify passes on persisted log', async () => {
    const log = new FileAuditLog({ keypair, path })
    const { valid, count } = await log.verify(keypair.publicKey)
    assert.equal(valid, true)
    assert.equal(count, 2)
  })

  test('verify fails on tampered operation field', async () => {
    const p = join(tmpdir(), `kxco-audit-tamper-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p })
      await log.append('keygen', { label: 'k1' })
      await log.close()
      const entry = JSON.parse(readFileSync(p, 'utf8').trim())
      entry.operation = 'delete'
      writeFileSync(p, JSON.stringify(entry) + '\n')
      const result = await new FileAuditLog({ keypair, path: p }).verify(keypair.publicKey)
      assert.equal(result.valid, false)
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })

  test('sealed: seals persist across instances alongside the entries', async () => {
    const p = join(tmpdir(), `kxco-audit-sealed-${process.pid}.ndjson`)
    try {
      const log1 = new FileAuditLog({ keypair, path: p, sealed: true })
      await log1.append('tool_call', { step: 0 })
      await log1.append('tool_call', { step: 1 })
      await log1.seal()
      await log1.close()

      const log2 = new FileAuditLog({ keypair, path: p, sealed: true })
      assert.equal((await log2.seals()).length, 1)
      const result = await log2.verify(keypair.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.count, 2)
      assert.equal(result.unsealed, 0)
    } finally {
      try { unlinkSync(p) } catch { /* ok */ }
      try { unlinkSync(p + '.seals') } catch { /* ok */ }
    }
  })

  test('appending in parallel does not fork the chain', async () => {
    const p = join(tmpdir(), `kxco-audit-parallel-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p, sealed: true })
      await Promise.all(
        Array.from({ length: 50 }, (_, i) => log.append('tool_call', { step: i }))
      )
      await log.seal()
      await log.close()

      const seqs = (await new FileAuditLog({ keypair, path: p, sealed: true }).export()).map(e => e.seq)
      assert.deepEqual(seqs, Array.from({ length: 50 }, (_, i) => i))
      const result = await new FileAuditLog({ keypair, path: p, sealed: true }).verify(keypair.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.count, 50)
      assert.equal(result.unsealed, 0)
    } finally {
      try { unlinkSync(p) } catch { /* ok */ }
      try { unlinkSync(p + '.seals') } catch { /* ok */ }
    }
  })

  test('a second writer is refused rather than allowed to fork the chain', async () => {
    const p = join(tmpdir(), `kxco-audit-twowriter-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p, sealed: true })
      await log.append('op1', {})
      writeFileSync(p, readFileSync(p, 'utf8') + '{"seq":1,"forged":true}\n')
      await assert.rejects(() => log.seal(), /Something else wrote to this log/)
      await assert.rejects(() => log.close(), /Something else wrote to this log/)
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })

  test('a torn final line is named, not skipped', async () => {
    const p = join(tmpdir(), `kxco-audit-torn-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p })
      await log.append('op1', {})
      await log.close()
      writeFileSync(p, readFileSync(p, 'utf8') + '{"seq":1,"timestamp":"2026-')
      await assert.rejects(
        () => new FileAuditLog({ keypair, path: p }).verify(keypair.publicKey),
        /line 2 is not valid JSON/
      )
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })

  test('stream() yields entries without loading the log', async () => {
    const p = join(tmpdir(), `kxco-audit-stream-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p, sealed: true })
      for (let i = 0; i < 5; i++) await log.append('tool_call', { step: i })
      await log.close()

      const seen = []
      for await (const entry of new FileAuditLog({ keypair, path: p, sealed: true }).stream()) {
        seen.push(entry.seq)
      }
      assert.deepEqual(seen, [0, 1, 2, 3, 4])
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })

  test('a missing file streams as an empty log rather than throwing', async () => {
    const p = join(tmpdir(), `kxco-audit-absent-${process.pid}.ndjson`)
    const result = await new FileAuditLog({ keypair, path: p }).verify(keypair.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.count, 0)
  })

  test('verify fails on broken prevHash chain', async () => {
    const p = join(tmpdir(), `kxco-audit-chain-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p })
      await log.append('op1', {})
      await log.append('op2', {})
      await log.close()
      const lines = readFileSync(p, 'utf8').trim().split('\n')
      const e2 = JSON.parse(lines[1])
      e2.prevHash = 'tampered'
      writeFileSync(p, lines[0] + '\n' + JSON.stringify(e2) + '\n')
      const result = await new FileAuditLog({ keypair, path: p }).verify(keypair.publicKey)
      assert.equal(result.valid, false)
      assert.match(result.error, /prevHash mismatch/)
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })
})

// ---------------------------------------------------------------------------
// Key rotation
//
// The gap this closes: verify() used to take one public key and apply it to
// every record, so a log that outlived a rotation could not be verified as a
// single artefact. There was no way to say "these entries were signed by the
// old key and those by the new one".
// ---------------------------------------------------------------------------

describe('key rotation', () => {
  const rotPath = join(tmpdir(), `kxco-audit-rotate-${process.pid}.ndjson`)
  const oldKey = mlDsa.ml_dsa65.keygen()
  const newKey = mlDsa.ml_dsa65.keygen()

  after(() => { try { unlinkSync(rotPath) } catch {} })

  async function writeRotatedLog() {
    try { unlinkSync(rotPath) } catch {}
    const before = new FileAuditLog({ keypair: oldKey, path: rotPath })
    await before.append('issued', { step: 1 })
    await before.append('issued', { step: 2 })
    await before.close()

    // The rotation: same file, new signing key.
    const after_ = new FileAuditLog({ keypair: newKey, path: rotPath })
    await after_.append('issued', { step: 3 })
    await after_.close()
  }

  test('a log spanning a rotation verifies when both keys are supplied', async () => {
    await writeRotatedLog()
    const reader = new FileAuditLog({ keypair: newKey, path: rotPath })
    const result = await reader.verify([oldKey.publicKey, newKey.publicKey])
    await reader.close()

    assert.equal(result.valid, true)
    assert.equal(result.count, 3)
    // Both keys actually signed, and the result says so rather than leaving the
    // caller to assume one of them was redundant.
    assert.equal(result.kids.length, 2)
  })

  test('the same log fails under either key alone, naming the missing one', async () => {
    await writeRotatedLog()
    const reader = new FileAuditLog({ keypair: newKey, path: rotPath })

    const withNewOnly = await reader.verify(newKey.publicKey)
    assert.equal(withNewOnly.valid, false)
    assert.match(withNewOnly.error, /entry 0: signed by kid [0-9a-f]{16}, which was not among/)

    const withOldOnly = await reader.verify(oldKey.publicKey)
    assert.equal(withOldOnly.valid, false)
    assert.match(withOldOnly.error, /entry 2: signed by kid [0-9a-f]{16}, which was not among/)
    await reader.close()
  })

  test('order of the supplied keys does not matter', async () => {
    await writeRotatedLog()
    const reader = new FileAuditLog({ keypair: newKey, path: rotPath })
    const a = await reader.verify([oldKey.publicKey, newKey.publicKey])
    const b = await reader.verify([newKey.publicKey, oldKey.publicKey])
    await reader.close()
    assert.equal(a.valid, true)
    assert.equal(b.valid, true)
  })

  test('signingKid matches the kid written onto entries', async () => {
    const log = new AuditLog({ keypair: oldKey })
    const entry = await log.append('op', {})
    assert.equal(entry.kid, log.signingKid)
    assert.match(entry.kid, /^[0-9a-f]{16}$/)
  })

  test('an entry with no kid still verifies, so logs written before this version do', async () => {
    // Simulates a log written by 1.3.x: same signed bytes, no kid selector.
    const log = new AuditLog({ keypair: oldKey })
    await log.append('op', {})
    const entries = await log.export()
    for (const e of entries) delete e.kid
    log._iterate = async function* () { for (const e of entries) yield e }

    const result = await log.verify(oldKey.publicKey)
    assert.equal(result.valid, true)
    assert.equal(result.count, 1)
  })

  test('a kid-less entry is still refused under the wrong key', async () => {
    const log = new AuditLog({ keypair: oldKey })
    await log.append('op', {})
    const entries = await log.export()
    for (const e of entries) delete e.kid
    log._iterate = async function* () { for (const e of entries) yield e }

    const result = await log.verify(newKey.publicKey)
    assert.equal(result.valid, false)
    assert.match(result.error, /entry 0: signature invalid/)
  })

  test('verify with no keys at all is an error, not a pass', async () => {
    const log = new AuditLog({ keypair: oldKey })
    await log.append('op', {})
    await assert.rejects(() => log.verify([]), /at least one public key/)
  })
})
