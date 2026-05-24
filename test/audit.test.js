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
    assert.match(result.error, /signature invalid/)
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

describe('FileAuditLog', () => {
  const path = join(tmpdir(), `kxco-audit-test-${process.pid}.ndjson`)
  after(() => { try { unlinkSync(path) } catch { /* ok */ } })

  test('persists entries across instances', async () => {
    const log1 = new FileAuditLog({ keypair, path })
    await log1.append('keygen', { label: 'k1' })
    await log1.append('sign',   { label: 'k1' })

    const log2 = new FileAuditLog({ keypair, path })
    const entries = await log2.export()
    assert.equal(entries.length, 2)
    assert.equal(entries[0].operation, 'keygen')
    assert.equal(entries[1].operation, 'sign')
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
      const entry = JSON.parse(readFileSync(p, 'utf8').trim())
      entry.operation = 'delete'
      writeFileSync(p, JSON.stringify(entry) + '\n')
      const result = await new FileAuditLog({ keypair, path: p }).verify(keypair.publicKey)
      assert.equal(result.valid, false)
    } finally { try { unlinkSync(p) } catch { /* ok */ } }
  })

  test('verify fails on broken prevHash chain', async () => {
    const p = join(tmpdir(), `kxco-audit-chain-${process.pid}.ndjson`)
    try {
      const log = new FileAuditLog({ keypair, path: p })
      await log.append('op1', {})
      await log.append('op2', {})
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
