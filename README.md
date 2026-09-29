# kxco-pq-audit

**A tamper-evident post-quantum audit trail: any edit, gap or reorder fails verification and names the entry.**

[![npm](https://img.shields.io/npm/v/kxco-pq-audit?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-audit)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-audit?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-audit)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-audit)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-audit)](https://socket.dev/npm/package/kxco-pq-audit)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-audit.svg)](https://nodejs.org)

Every operation produces a signed entry: an ML-DSA-65 signature, SHA-256 chained to the previous entry. `verify()` replays the entire log, and any gap, reorder or edit breaks the chain or a signature.

- **Tampering is detectable and locatable.** `verify()` replays the log from entry 0 and names the first entry that fails.
- **Fast enough for real volume.** Sealed mode signs once per run: 46,544 entries a second at 367 bytes an entry, with 10,000 entries verified in 0.11 s, per [Sealed logs](#sealed-logs).
- **Verifies across key rotation.** Pass every key the log was signed under and it verifies as one artefact, with each entry naming the kid that signed it.
- **Streams, so size is no limit.** Memory stays bounded by one entry: 50,000 entries verify in 729 ms, per [`log.verify`](#logverifypublickey).
- **An anchor a regulator can confirm.** Checkpoints on Armature L1 prove that at least N entries existed at a given block height.
- **Built for auditors.** Evidence for SOC 2 and ISO 27001 controls that a third party can check without trusting the log operator.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Sealed logs](#sealed-logs) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

Use this when you need a cryptographic proof that a sequence of operations happened, in order, and was not altered after the fact.

Designed for:

- Financial institutions logging transaction authorisations, key ceremonies, and administrative actions
- Compliance teams that need an immutable audit trail reviewable by external auditors
- SOC 2 and ISO 27001 implementations requiring evidence that access and operations cannot be silently edited
- Any system where "the log said X happened" must be verifiable by a third party without trusting the log operator

It is a cryptographic integrity primitive: a chain of signed, hash-linked records that proves the log is exactly as written.

## Install

```
npm install kxco-pq-audit
```

## Quick start

```js
import { FileAuditLog } from 'kxco-pq-audit'
import { KxcoChain }    from 'kxco-pq-chain'   // optional, for anchoring
import { mlDsa }        from 'kxco-post-quantum'

const keypair = mlDsa.ml_dsa65.keygen()

// Persist to disk, anchor a checkpoint on Armature L1 every 50 entries
const chain = new KxcoChain({
  identity:   institutionIdentity,           // a KxcoIdentity from kxco-pq-sdk
  licenceKey: process.env.KXCO_LICENCE_KEY,  // the hosted anchoring service
})
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

const entries = await log.export()
// array of signed entry objects
```

Chain anchoring is optional. Remove the `chain` and `checkpointEvery` options to run without it.

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

### `new AuditLog(options)`

In-memory log, for tests and short-lived processes. Use `FileAuditLog` to persist.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `keypair` | `{ secretKey, publicKey }` | Yes | none | ML-DSA-65 keypair from `kxco-post-quantum` |
| `chain` | `KxcoChain` | No | `null` | Chain instance for checkpoint anchoring |
| `checkpointEvery` | `number` | No | `100` | Anchor a checkpoint every N entries |
| `institutionKid` | `string` | No | `null` | Identifier included in checkpoint metadata |
| `sealed` | `boolean` | No | `false` | Sign once per run instead of once per entry. See [Sealed logs](#sealed-logs) |

### `new FileAuditLog(options)`

Append-only NDJSON file backend. Survives process restarts. Accepts all the same options as `AuditLog`, plus:

| Option | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | Yes | Path to the `.ndjson` file (created if absent) |
| `idleReleaseMs` | `number` | No | Release the write handle after this long without a write (default `2000`) |

Entries are read as a stream and never all at once, and writes go through one handle held open while the log is busy. Both mean cost per entry does not grow with the file.

**One file has one writer.** A signed chain cannot have two: both would build on the same tail and the second entry would take the first one's place. Every seal and every `close()` checks the file is the size this instance left it, and throws if it is not.

### `log.close()`

`FileAuditLog` only. Releases the write handle. Not required, since the handle is released after `idleReleaseMs` without a write, but call it when you want the descriptor back at a known point. Throws if another writer has touched the file.

### `log.append(operation, metadata)`

Appends a signed, hash-chained entry.

- `operation`: non-empty string identifying the operation (e.g. `'wire.auth'`, `'key.rotate'`)
- `metadata`: plain object, serialised into the signed payload
- Returns the entry object

If chain anchoring is configured and the entry count is a multiple of `checkpointEvery`, a fire-and-forget checkpoint is sent to the relay. The `append` call resolves immediately, without waiting for the chain.

Appending needs the previous entry's hash, not the log, so it costs the same on ten entries and on ten million. Concurrent calls are serialised internally: two appends in flight together cannot take the same `seq`.

### `log.verify(publicKey)`

Replays the entire log from entry 0. For each entry, checks:

1. `prevHash` matches the SHA-256 of the previous entry (including its signature)
2. The ML-DSA-65 signature is valid over the canonical signing bytes

Returns `{ valid: true, count, kids }` or `{ valid: false, error }` describing the first failure. On a sealed log it checks the chain and every seal instead, and adds `sealedThrough` and `unsealed`.

It streams, so memory is bounded by one entry rather than by the log: 50,000 entries verify in 729 ms without holding them, per [ASSESSMENT.md](./ASSESSMENT.md).

#### Logs that outlive a key rotation

A long-lived log will outlast the key it started with. Pass every key it was signed under and it verifies as one artefact:

```js
const result = await log.verify([oldKey.publicKey, newKey.publicKey])
// { valid: true, count: 3, kids: ['a1b2…', 'c3d4…'] }
```

Each entry records the `kid` of the key that signed it, so verification selects the right key rather than trying to force one across the whole file. `kids` reports which keys actually signed, in the order first seen. More than one means the log spans a rotation.

Supply too few keys and the failure names what is missing, rather than reporting a generic bad signature:

```
entry 0: signed by kid a1b2c3d4e5f60718, which was not among the 1 key(s) supplied
```

Order does not matter. Entries written before 1.4.0 carry no `kid` and are checked against each supplied key in turn, so **older logs verify unchanged**, and because `kid` is not part of the signed bytes, logs written by 1.4.0 still verify under 1.3.x.

Recording the kid is also what makes a log answerable to the rest of the stack. Before 1.4.0 an entry named no key, so there was nothing to look up. Every `kid` in `kids` is the identifier [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) resolves against the registry as `active`, `revoked`, `rotated` or `expired`, and that [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain)'s `revokeKid()` writes on chain.

Pair `verify()` with that lookup and a log proves both that it is intact and
that every signing key was trusted: live revocation, from the KXCO network.

### `log.seal()`

Sealed logs only. Signs everything appended since the last seal, as one run, and returns the seal. Returns `null` when nothing is unsealed, and throws on a log built without `sealed: true`.

If chain anchoring is configured, the run's root is anchored fire-and-forget. A sealed log anchors when it seals rather than every `checkpointEvery` entries.

### `log.seals()`

Sealed logs only. Returns every seal, oldest first.

### `log.export()`

Returns all entries as an array, in seq order. Holds the whole log in memory by definition; prefer `stream()` on a large one.

### `log.stream()`

Yields entries one at a time, in seq order. Memory stays bounded by a single entry however long the log is.

```js
for await (const entry of log.stream()) {
  if (entry.operation === 'tool_call') console.log(entry.seq, entry.metadata.tool)
}
```

### `log.unsealedCount()`

Sealed logs only. Entries appended since the last seal, without replaying the log. Always `0` on a classic log.

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

## Sealed logs

By default every entry carries its own ML-DSA-65 signature. That signature is also the entire cost of the log. Measured over 10,000 entries, per [ASSESSMENT.md](./ASSESSMENT.md):

| | entries/s | bytes/entry | 10k run | verify |
|---|---|---|---|---|
| signature per entry | 129 | 4,794 | 45.7 MB | 20.1 s |
| signature per run | 46,544 | 367 | 3.5 MB | 0.11 s |

Of those 4,794 bytes, per [ASSESSMENT.md](./ASSESSMENT.md), 4,412 are the base64url-encoded signature, which is why sealed mode is the one for real entry volume.

`sealed: true` keeps the hash chain on every entry and moves the signature to the run:

```js
const log = new AuditLog({ keypair, sealed: true })

for (const call of agentToolCalls) {
  await log.append('tool_call', call)   // chained, not signed
}

const seal = await log.seal()           // one signature for the whole run
// { fromSeq: 0, toSeq: 9999, entryCount: 10000, prevRoot, rootHash, timestamp, signature }
```

The chain is what detects tampering, and it is untouched. An entry edited, removed, reordered or inserted after sealing fails to reproduce the run's `rootHash`. Seals chain to one another by `prevRoot`, so removing a whole seal breaks the seal that follows it.

`verify()` on a sealed log reports where the signed record stops:

```js
await log.verify(publicKey)
// { valid: true, count: 10002, sealedThrough: 9999, unsealed: 2 }
```

Entries appended since the last seal are chained and awaiting a signature. `unsealed` reports that window, and `seal()` closes it. A sealed entry verifies as part of its run.

`FileAuditLog` writes seals to `<path>.seals`, so a reader that knows only about entries is unaffected.

## Chain anchoring

When you pass a chain and set `checkpointEvery`, every Nth entry triggers a call to `chain.anchorAuditRoot({ rootHash, entryCount })` via the KXCO relay.

The anchor is fire-and-forget: `append` does not await it, so chain latency never blocks audit operations. If the relay call fails, a warning is written to stderr and the local log continues unaffected.

The checkpoint provides an on-chain timestamp proving that at least N entries existed at a specific block height. This supplements the local NDJSON file for long-term tamper evidence, particularly where the log operator and the verifier are separate parties.

## The KXCO post-quantum family

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

[kxco.ai](https://kxco.ai) · [Knightsbridge Law](https://knightsbridgelaw.com) · [target150.com](https://target150.com)

## Release integrity

Every release since 1.2.0 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-audit@<version>`. A CycloneDX
SBOM is published, from v1.2.1, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.2.0: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.2.1
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

The hash chain means a compromised or deleted entry cannot be hidden: any gap breaks verification of every subsequent entry.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-audit/security/advisories/new) or email **security@kxco.ai**.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
