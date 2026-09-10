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

**Retain history: the limitation that matters.** `verify(publicKey)` takes one
public key and applies it to the whole log. A log whose signing key was rotated
part-way through cannot be verified as a single artefact, because entries
before the rotation were signed by a key `verify` is no longer being given.

There is no key identifier in the entry format and no validity window, so the
package cannot select the right key per entry, and it cannot tell you a key was
still trusted when a signature was made. Long-lived logs need either one key
for the life of the log, or a segmentation strategy the caller imposes from
outside. This is the open long-term-validation question for the KXCO stack and
it is not solved here.

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

That is 361x the append rate, a thirteenth of the bytes and verification in
about a two-hundredth of the time, for the same tamper evidence: every entry is
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
