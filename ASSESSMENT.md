# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when keys and algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

An append-only record whose tampering is detectable and locatable. Entries are
SHA-256 hash-chained and ML-DSA-65 signed, so **an edited or deleted entry
fails `verify()` and the failure names the entry**. That is the guarantee, and
it is the reason to use this rather than a table with a timestamp column.

**Two modes, and the second is what makes it viable at volume.** By default
every entry carries its own signature. In sealed mode entries are chained and
`seal()` signs the run once. Measured over a 10,000 entry run:

| | entries/s | bytes/entry | 10k run | verify |
|---|---|---|---|---|
| signature per entry | 129 | 4,794 | 45.7 MB | 20.1 s |
| signature per run | 46,544 | 367 | 3.5 MB | 0.11 s |

361x the append rate, a thirteenth of the bytes, verification 183x faster, and
the tamper evidence is identical: every entry is still hash-chained, and the
signature binding the run to the key is produced once instead of ten thousand
times. Agent-scale volume is a solved problem here, and the numbers are in the
README to be reproduced.

**Writes are serialised, so the chain cannot fork.** Two appends in flight
would otherwise read the same tail and mint the same `seq`. They go through a
queue, which is the difference between a chain that is strongest under load and
one that is weakest.

**Verification streams.** Memory is bounded by one entry and the seal list
rather than by the log: 50,000 entries verify in 729 ms without holding them.

**An unsealed tail is never counted as proven.** `verify()` reports
`sealedThrough` and `unsealed` separately, so the window between the last seal
and the newest entry is visible rather than quietly folded into a pass.

**Time is anchored where it matters.** Entry timestamps are the operator's
clock, signed so they cannot be altered after the fact. For an independent
bound, a checkpoint anchors the run's root on Armature L1, proving at least N
entries existed at a given block height, which is what a regulator or a
counterparty who does not trust the log operator can confirm on chain.
Anchoring is fire-and-forget so chain latency never blocks an audit write.

## Keys, over the life of a log

A record that must outlive its signing key is the hard case, and it is handled.

Entries and seals record the `kid` of the key that signed them, `verify()`
accepts an array of keys, and each record is checked against the key its kid
names:

```js
await log.verify([oldKey.publicKey, newKey.publicKey])
// { valid: true, count: 3, kids: ['a1b2…', 'c3d4…'] }
```

`kids` reports which keys actually signed, in the order first seen. Supply too
few and the failure names the one that is missing, rather than reporting a
generic bad signature. `log.signingKid` exposes the kid a log is currently
writing with.

**Compatible in both directions, by design.** The kid is not part of the signed
bytes. Including it would have forced a new signing-message version and every
log written here would have stopped verifying under an older reader. As a
selector it cannot make a forged record verify, because that still needs a key
the verifier was given, and tampering with it produces the same refusal
tampering with anything else already produces. So logs written by 1.4.0 verify
under 1.3.x, logs written before 1.4.0 verify here, and passing a single key
behaves exactly as it always did.

**It also makes a log answerable to the rest of the stack.** Every kid is the
identifier [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network)
resolves against the registry as `active`, `revoked`, `rotated` or `expired`,
and that [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain)'s
`revokeKid()` writes on chain, where the credential carries `expiresAt`. This
package proves which key signed; those resolve whether it should be trusted.
That division is deliberate: verification here stays offline and dependency-free,
and a caller who wants key status has an explicit place to ask.

## Scope

This package writes and verifies a file. Search belongs in a database you index
into, because reading is line by line by design. Nothing in `src/` opens a
socket: chain anchoring goes through a `chain` object the caller injects, so the
network call belongs to whatever implements it, normally `kxco-pq-chain`.

Single-writer per file. The in-process queue makes concurrent appends safe
within a process, which is the deployment shape this is built for.

## Agility

**Inherited.** The signature primitive and its two interchangeable backends
belong to `kxco-post-quantum`.

**Versioned formats.** Signed bytes are domain-separated and prefixed,
`kxco-audit-v1` for entries and `kxco-audit-seal-v1` for seals, so a v2 format
can be introduced without a v1 signature becoming ambiguous. That is the
mechanism a format migration needs, present before it is needed, and the kid
work above is the proof it functions: a change shipped without breaking a single
existing log in either direction.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.
All checkable without asking us for anything.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware ceiling. Append is O(1) whether the log holds ten entries
or ten million: a new entry needs the previous hash and the next seq, never the
log. The throughput table above is the sizing guide.

**Runtime.** Node 20.19 and later, with Node 24 and later running the primitives
in OpenSSL 3.5 for roughly 4x to 8x per operation.

## Correcting this document

Every figure here is reproducible from this repository. If one does not match,
that is a defect worth reporting through the repository's issues.
