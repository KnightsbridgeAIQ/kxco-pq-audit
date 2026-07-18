# kxco-pq-audit

[![npm](https://img.shields.io/npm/v/kxco-pq-audit?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-audit)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-audit)](https://socket.dev/npm/package/kxco-pq-audit)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-audit.svg)](https://nodejs.org)

Tamper-evident post-quantum audit log. Every operation produces an ML-DSA-65-signed entry chained to the previous via SHA-256. `verify()` replays the entire log — any gap, reorder, or edit breaks the chain or a signature.

## When to use this

Use this when you need a cryptographic proof that a sequence of operations happened, in order, and was not altered after the fact.

Designed for:

- Financial institutions logging transaction authorisations, key ceremonies, and administrative actions
- Compliance teams that need an immutable audit trail reviewable by external auditors
- SOC 2 and ISO 27001 implementations requiring evidence that access and operations cannot be silently edited
- Any system where "the log said X happened" must be verifiable by a third party without trusting the log operator

This is not a logging framework. It is a cryptographic integrity primitive — a chain of signed, hash-linked records that proves the log has not been tampered with.

## Install

```
npm install kxco-pq-audit
```

## Quick start

```js
import { FileAuditLog } from 'kxco-pq-audit'
import { KxcoChain }    from 'kxco-pq-chain'   // optional — omit if not anchoring
import { mlDsa }        from 'kxco-post-quantum'

const keypair = mlDsa.ml_dsa65.keygen()

// Persist to disk, anchor a checkpoint on Armature L1 every 50 entries
const chain = new KxcoChain({ endpoint: 'https://relay.kxco.ai' })
const log = new FileAuditLog({
  keypair,
  path: './audit.ndjson',
  chain,
  checkpointEvery: 50,
})

await log.append('user.login',  { userId: 'u_001', ip: '10.0.0.1' })
await log.append('wire.auth',   { txId: 'tx_abc', amount: 50000, currency: 'USD' })
await log.append('key.rotate',  { keyId: 'signing-key-v2', alg: 'ml-dsa-65' })

const result = await log.verify(keypair.publicKey)
// { valid: true, count: 3 }

const entries = await log.entries()
// array of signed entry objects
```

Chain anchoring is optional. Remove the `chain` and `checkpointEvery` options to run without it.

## API

### `new AuditLog(options)`

In-memory log. Entries are lost when the process exits.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `keypair` | `{ secretKey, publicKey }` | Yes | — | ML-DSA-65 keypair from `kxco-post-quantum` |
| `chain` | `KxcoChain` | No | `null` | Chain instance for checkpoint anchoring |
| `checkpointEvery` | `number` | No | `100` | Anchor a checkpoint every N entries |
| `institutionKid` | `string` | No | `null` | Identifier included in checkpoint metadata |

### `new FileAuditLog(options)`

Append-only NDJSON file backend. Survives process restarts. Accepts all the same options as `AuditLog`, plus:

| Option | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | Yes | Path to the `.ndjson` file (created if absent) |

### `log.append(operation, metadata)`

Appends a signed, hash-chained entry.

- `operation` — non-empty string identifying the operation (e.g. `'wire.auth'`, `'key.rotate'`)
- `metadata` — plain object, serialised into the signed payload
- Returns the entry object

If chain anchoring is configured and the entry count is a multiple of `checkpointEvery`, a fire-and-forget checkpoint is sent to the relay. The `append` call resolves immediately — it does not wait for the chain.

### `log.verify(publicKey)`

Replays the entire log from entry 0. For each entry, checks:

1. `prevHash` matches the SHA-256 of the previous entry (including its signature)
2. The ML-DSA-65 signature is valid over the canonical signing bytes

Returns `{ valid: true, count }` or `{ valid: false, error }` describing the first failure.

### `log.entries()`

Returns all entries as an array. Equivalent to `log.export()`.

## Entry format

```json
{
  "seq": 0,
  "timestamp": "2026-05-24T07:29:22.000Z",
  "operation": "wire.auth",
  "metadata": { "txId": "tx_abc", "amount": 50000 },
  "prevHash": null,
  "signature": "<base64url ML-DSA-65>"
}
```

`prevHash` is the SHA-256 of the complete previous entry (signature included). The first entry always has `prevHash: null`. The signing message covers every field except `signature` itself.

## Chain anchoring

When a `chain` is passed and `checkpointEvery` is set, every Nth entry triggers a call to `chain.anchorAuditRoot({ rootHash, entryCount })` via the KXCO relay.

The anchor is fire-and-forget: `append` does not await it, so chain latency never blocks audit operations. If the relay call fails, a warning is written to stderr and the local log continues unaffected.

The checkpoint provides an on-chain timestamp proving that at least N entries existed at a specific block height. This supplements the local NDJSON file for long-term tamper evidence, particularly where the log operator and the verifier are separate parties.

## What this does NOT do

- **Not a database.** Entries cannot be queried by field, filtered, or indexed. Read the file line by line.
- **Not queryable.** There is no search API. If you need search, index entries into a database alongside the NDJSON file.
- **Append-only.** Entries cannot be edited or deleted without breaking `verify()`. This is intentional.
- **Not a transport.** This package writes and verifies. It does not expose HTTP endpoints or stream entries to external systems.

## Part of the KXCO stack

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 primitives |
| [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) | HSM-backed key management |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | `AuditedHsm` — wires HSM + audit log automatically |
| [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) | Armature L1 relay for checkpoint anchoring |

[kxco.ai](https://kxco.ai) · [Knightsbridge Law](https://knightsbridge.law) · [target150.com](https://target150.com)

## Security

Entry signing uses [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum) ML-DSA-65 (NIST FIPS 204) and [Noble hashes](https://github.com/paulmillr/noble-hashes) SHA-256 — independently audited by Cure53 (2024). The hash chain means a compromised or deleted entry cannot be hidden: any gap breaks verification of every subsequent entry.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-audit/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)
