# Changelog

## 1.4.0

A log that outlives its signing key can now be verified as one artefact.

**`verify()` accepts several public keys.** It took one, and applied it to every
record, so a log whose key rotated part-way through could not be verified at
all: entries before the rotation were signed by a key `verify` was no longer
being given. Hierarchical credentials exist so that keys can change, which made
this the gap most likely to be hit by the deployments least able to work around
it.

```js
await log.verify([oldKey.publicKey, newKey.publicKey])
// { valid: true, count: 3, kids: ['a1b2…', 'c3d4…'] }
```

**Entries and seals record a `kid`.** Sixteen hex characters naming the key that
signed them, so verification selects the right key instead of forcing one across
the whole file. `log.signingKid` exposes the same value for the key a log is
writing with. `verify()` returns `kids`, every key that actually signed, in the
order first seen; more than one means the log spans a rotation.

**A missing key is now named.** Supplying too few keys reports which one is
absent rather than a generic bad signature:

```
entry 0: signed by kid a1b2c3d4e5f60718, which was not among the 1 key(s) supplied
```

That message replaces `entry N: signature invalid` for this case. A wrong key
that shares no kid with the record is still refused; only the wording changed.

**Compatible in both directions, deliberately.** `kid` is not part of the signed
bytes. Including it would have meant a new signing-message version, and every
log written here would have stopped verifying under an older reader. So logs
written by 1.4.0 verify under 1.3.x, and logs written before 1.4.0 carry no kid
and are checked against each supplied key in turn. Passing a single key keeps
working exactly as before.

As a selector rather than a claim, a tampered `kid` makes verification pick the
wrong key and fail. It cannot make a forged record verify, because that still
needs a key the verifier was given.

**Still not solved: validity.** No validity window, no revocation. `kids` says
which keys signed, not that they were trusted when they did.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**An evidence bundle.** `npm run evidence` records identity, this package's own
tests, its SBOM, registry signature verification, and the `kxco-post-quantum`
version actually installed rather than the range declared.

## 1.3.1

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**`npm run evidence` now exists.** The README already told you to run it and
there was no such script, so the command failed for anyone who followed it.
The bundle records identity, this package's own tests, its SBOM, registry
signature verification, and the `kxco-post-quantum` version actually installed
rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.4.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

## 1.3.0

### Added

`sealed: true` signs once per run instead of once per entry.

Every entry is still hash-chained, which is what detects an edit, a removal, a
reorder or an insertion. The per-entry signature only bound one entry to the
key, and it was the entire cost of the log. Measured here on ML-DSA-65 over
10,000 entries:

| | entries/s | bytes/entry | verify |
|---|---|---|---|
| per entry | 129 | 4,794 | 20.1 s |
| per run | 46,544 | 367 | 0.11 s |

Of those 4,794 bytes, 4,412 were the signature. Any workload with real entry
volume, agent tool calls being the case this was built for, cannot afford one
signature per entry.

`seal()` returns the run it signed, or null when nothing is unsealed. `seals()`
returns them all. Seals chain to each other by `prevRoot`, so removing an entire
seal breaks the one after it, the same way removing an entry breaks the next
entry's `prevHash`. `FileAuditLog` writes them to `<path>.seals`.

`verify()` on a sealed log reports `sealedThrough` and `unsealed`. Entries
appended since the last seal are chained and unsigned, and that window is
reported rather than counted as proven.

Two things it costs: a single entry can no longer be verified on its own, only
as part of its run, and the unsealed window is real until `seal()` runs.

Default is unchanged. A log built without the option behaves exactly as before,
signature per entry included.

`stream()` yields entries one at a time, and `unsealedCount()` reports the
window without replaying the log.

### Fixed

**Concurrent appends forked the chain.** Every `append()` read the log to find
the next seq, so two in flight together both read the same tail and both claimed
it. Fifty parallel appends produced fifty entries all numbered `seq 0`, and the
resulting log fails its own `verify()`. Writes are now serialised internally, so
the same fifty produce seq 0 to 49 and verify clean. Any log written
concurrently under 1.2.3 or earlier should be checked with `verify()`.

**Appending was quadratic.** `append()` loaded every entry to work out the next
seq and prevHash, and `FileAuditLog` re-read and re-parsed the whole file each
time. A log now loads once and keeps only the tail, so cost per entry no longer
depends on length.

| entries | before | after |
|---|---|---|
| 500 | 1,635 us/entry | 66 us/entry |
| 2,000 | 2,279 us/entry | 66 us/entry |
| 4,000 | 3,262 us/entry | 66 us/entry |
| 50,000 | not measured, still climbing | 66 us/entry |

`FileAuditLog` also holds one write handle rather than reopening the file per
entry, which is ~46us a write against ~421us. It is released after 2 seconds
idle, so forgetting `close()` costs nothing, and `close()` is there for a
deterministic hand-back.

**`verify()` loaded the whole log to check it.** It now streams, so memory is
bounded by one entry and the seal list. 50,000 entries verify in 729 ms.

### Added, smaller

`FileAuditLog` refuses to append to a file that changed size underneath it,
rather than forking the chain and failing much later at `verify()`. One file has
one writer; `assertSoleWriter()` checks it on demand and runs on every seal and
close.

A line that will not parse is now named with its line number and told apart from
a torn final line, instead of surfacing as a bare `SyntaxError`.

## 1.2.3

### Corrected

The README claimed `@noble/post-quantum` was audited by Cure53 in 2024.
It is maintainer-audited (v0.6.1, April 2026), not Cure53-audited.

The other Noble packages were audited separately and at different dates, and
none of those engagements reached the post-quantum package:

| Package | Audited by |
|---|---|
| `@noble/post-quantum` | maintainer-audited |
| `@noble/hashes` | Cure53, Jan 2022, v1.0.0 |
| `@noble/curves` | Trail of Bits Feb 2023; Kudelski Sep 2023; Cure53 Sep 2024 |
| `@noble/ciphers` | Cure53, Sep 2024, v1.0.0 |

Dates from `kxco-post-quantum/audit/dependency-review.json`, which is generated
by `audit/run-audit.mjs` rather than written by hand.

Documentation only. No code changed and no behaviour changed.

`.socket.yml` said `@noble/hashes` was audited by Cure53 in 2024. The audit
was real but the date was wrong: January 2022, at v1.0.0.
