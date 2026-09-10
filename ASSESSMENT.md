# Assessment notes

What a buyer assessing this package needs that the README does not tell them:
where the product boundary falls, what cryptographic agility it has, and what
constrains its lifecycle.

This package does not implement ML-DSA, ML-KEM or SLH-DSA. It calls
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs the NIST ACVP vectors and the cross-implementation interoperability matrix
and publishes them in its own evidence bundle. Algorithm conformance is a claim
about that package, is referenced here, and is deliberately not restated. A
second copy of a conformance claim invites you to count it twice.

## Boundary

**What the assessed thing is.** A library that writes and verifies an
append-only NDJSON file. One storage backend exists, `src/backends/file.js`.

**Operate: no network of its own.** Nothing in `src/` opens a socket. Chain
anchoring happens through a `chain` object the caller injects, so the network
call belongs to whatever implements it, normally
[`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain). Assess that
package for the connection; this one only calls a method.

**Operate: writes are serialised.** Appends run through a promise queue,
because two appends in flight would read the same tail and mint the same `seq`,
forking the chain at the point it is supposed to be strongest. That is a
property of a single process. Two processes appending to one file is not a
supported configuration and there is no lock that would make it one.

**Protect records.** This is the package's whole purpose, so state the parts
separately:

- *Integrity* is a SHA-256 hash chain over entries, plus an ML-DSA-65
  signature. In default mode every entry is signed. In sealed mode entries are
  chained and unsigned, and `seal()` signs the run once, which is what makes
  high append rates affordable.
- *Timestamps in an entry are the local clock.* They are signed, so they cannot
  be altered after the fact, and a signed clock is still the operator's clock.
  They are not a trusted time source and nothing here claims they are.
- *The independent time bound is the on-chain checkpoint*, which proves at
  least N entries existed at a given block height. Anchoring is deliberately
  fire-and-forget: `append` does not await it so chain latency never blocks an
  audit write, and a failed anchor writes a warning to stderr while the log
  continues.

  The consequence is worth stating plainly. A log with no anchor and a log
  whose anchor call failed look identical from the file alone. If the anchor is
  part of your control, monitor that it happened; the log will not tell you.

**Start and update.** This package has no release signing of its own. The
primitives package signs its release assets with ML-DSA-65 against a committed
public key, and that is the stronger control of the two; it should not be read
across to this one.

What this package's releases do carry is not nothing:

- A **SLSA provenance attestation** on every release, tying the tarball to the
  commit and workflow that built it. Verify with `npm audit signatures`.
- A **CycloneDX SBOM** as a GitHub Release asset at a permanent unauthenticated
  URL, rather than an expiring build artifact.
- An **evidence bundle** from `npm run evidence`, recording identity, the test
  run, the SBOM and the `kxco-post-quantum` version actually installed.

**Retain history: rotation is handled, validity is not.**

Until 1.4.0 `verify(publicKey)` took one key and applied it to the whole log, so
a log whose signing key rotated part-way through could not be verified as a
single artefact. That is fixed. Entries and seals record the `kid` of the key
that signed them, `verify` accepts an array, and each record is checked against
the key its kid names:

```js
await log.verify([oldKey.publicKey, newKey.publicKey])
// { valid: true, count: 3, kids: ['a1b2…', 'c3d4…'] }
```

Two properties worth an assessor's attention. The `kid` is **not** part of the
signed bytes, deliberately: including it would have meant a new signing-message
version and every log written here would have stopped verifying under an older
reader. As a selector it cannot make a forged record verify, because that still
needs a key the verifier was given, and tampering with it produces the same
refusal tampering with anything else already produced. And a record naming a key
that was not supplied fails with that fact rather than a generic bad signature,
which is the difference between "go and find the old key" and "something is
wrong".

Records written before 1.4.0 carry no kid and are checked against each supplied
key in turn, so older logs verify unchanged.

**Key status: this package now emits what resolves it.** Recording the `kid` is
what makes an audit log answerable to the rest of the stack. Before 1.4.0 an
entry named no key, so there was nothing to look up; now every entry carries the
identifier that [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network)
resolves against the registry as `active`, `revoked`, `rotated` or `expired`,
and that [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain)
`revokeKid()` writes on chain. The on-chain credential carries `expiresAt`,
which is where the validity window lives.

Keep the boundary straight, because it is the useful part. This package proves
which key signed each entry and that the chain is intact. It does not decide
whether that key should have been trusted, and it makes no network call to find
out. What changed is that the question is now answerable at all: a verifier
holding `kids` can put each one to the registry, which is precisely the
composition `kxco-pq-sdk` assembles.

What no package in the stack does is bind the two automatically. `verify()` will
not refuse an entry signed by a since-revoked key, because it does not know and
does not ask, and a key compromised later verifies exactly as cleanly as one
that was not. Pairing the two is the caller's, and the on-chain checkpoint
remains the only thing pinning a signature to a point in time.

## Agility

Inherited, with one addition and one hard limit.

**Inherited.** The signature primitive, its two interchangeable backends and
the parameter-set surface all belong to `kxco-post-quantum`. See that package's
`AGILITY.md`. Nothing in this package constrains which backend runs.

**The addition: the format carries a version.** Signed bytes are domain
separated and prefixed, `kxco-audit-v1` for entries and `kxco-audit-seal-v1`
for seals. A v2 entry format can therefore be introduced without a v1 signature
becoming ambiguous, which is the property a format migration needs.

**The limit: the algorithm is not selectable.** Entries are signed with
ML-DSA-65 and there is no algorithm field in the entry. A move to a different
parameter set is a format change and a release of this package, not a
configuration. Given the file is the artefact and old entries have to keep
verifying, that is the conservative choice, and it is a ceiling rather than a
feature.

## Lifecycle

**Supported versions.** One line moving forward, matching the rest of the
family. Fixes land in the next release rather than being backported.

**The primitives are declared as a range, and that is the assessed-configuration
problem.** This package declares `kxco-post-quantum` as `^1.3.0`. The primitives
package states, in its own `SECURITY.md`, that a range would let the code that
runs the cryptography change without a release, and pins its own dependencies
exactly for that reason. We do not apply the same rule here.

The practical effect is measurable rather than theoretical: the tree this
package's evidence bundle was last built from resolved `^1.3.0` to **1.4.0**,
old enough to predate `backend()`, so it could not even report which
implementation performed the signatures. `02-primitives.json` in the bundle
records the resolved version for exactly this reason. Read it before treating
any claim here as applying to your install.

Changing this is a policy decision with a maintenance cost: an exact pin means
every primitives release needs a release of this package. It has not been made.

**Ceiling.** No hardware ceiling. One storage backend, and reads are line by
line, so search belongs in a database you index into rather than here.

The throughput ceiling is real in default mode and sealed mode removes it, by
a margin worth stating rather than glossing. Measured over a 10,000 entry run
and published in the README:

| | entries/s | bytes/entry | 10k run | verify |
|---|---|---|---|---|
| signature per entry | 129 | 4,794 | 45.7 MB | 20.1 s |
| signature per run | 46,544 | 367 | 3.5 MB | 0.11 s |

That is 361x the append rate, a thirteenth of the bytes and verification 183x
faster, for the same tamper evidence: every entry is
still hash-chained, and the signature that binds the run to the key is produced
once by `seal()` instead of once per entry. A deployment that dismissed
per-entry signing on cost grounds should read the second row before deciding
this package cannot carry its volume.

**Roadmap.** No external audit of this package, no bug bounty, no module
certification. The primitives package publishes its roadmap in `AUDIT.md`;
nothing equivalent has been committed for this one.

## Correcting this document

Every claim here is checkable against `src/`. If one does not match, that is a
defect worth reporting through the repository's issues.
