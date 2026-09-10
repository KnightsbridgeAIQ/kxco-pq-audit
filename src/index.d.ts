/// <reference types="node" />

export interface AuditEntry {
  seq:       number
  timestamp: string
  operation: string
  metadata:  Record<string, unknown>
  /** SHA-256 of the previous entry (entire JSON including signature). Null for the first entry. */
  prevHash:  string | null
  /**
   * base64url ML-DSA-65 signature over a canonical representation of all other
   * fields. Absent on a sealed log, where the run is signed once by `seal()`.
   */
  signature?: string
  /**
   * 16 hex characters identifying the key that signed this entry, present from
   * 1.4.0. Absent on entries written by earlier versions and on sealed logs,
   * where the seal carries it instead.
   *
   * Not part of the signed bytes: it selects a key rather than asserting one.
   * Tampering with it makes verification pick the wrong key and fail; it cannot
   * make a forged entry verify.
   */
  kid?: string
}

/** One signed run of a sealed log. Seals chain to each other by `prevRoot`. */
export interface AuditSeal {
  fromSeq:    number
  toSeq:      number
  entryCount: number
  /** The previous seal's rootHash, or 64 zeroes for the first seal. */
  prevRoot:   string
  /** base64url SHA-256 over prevRoot followed by every entry hash in the run. */
  rootHash:   string
  timestamp:  string
  /** base64url ML-DSA-65 signature over the seal's canonical form. */
  signature:  string
  institutionKid: string | null
  /**
   * 16 hex characters identifying the key that signed this seal, present from
   * 1.4.0. Distinct from `institutionKid`, which names the institution rather
   * than the signing key.
   */
  kid?: string
}

export interface AuditVerifySuccess {
  valid: true
  count: number
  /**
   * Sealed logs only: the highest seq covered by a verified seal, or -1 when
   * nothing is sealed yet.
   */
  sealedThrough?: number
  /**
   * Sealed logs only: entries appended since the last seal. They are chained
   * but carry no signature. A non-zero value is not a failure and is not proof
   * either — seal() closes the window.
   */
  unsealed?: number
  /**
   * Every signing key that actually produced a signature in this log, in the
   * order first seen. More than one means the log spans a key rotation.
   */
  kids: string[]
}

export interface AuditVerifyFailure {
  valid: false
  error: string
}

export type AuditVerifyResult = AuditVerifySuccess | AuditVerifyFailure

/** Minimal chain client interface — accepts kxco-pq-chain KxcoChain instances */
export interface AuditChainClient {
  anchorAuditRoot(opts: { rootHash: string; entryCount: number }): Promise<unknown>
}

export interface AuditLogOptions {
  keypair: {
    publicKey: Uint8Array | Buffer
    secretKey: Uint8Array | Buffer
  }
  /** kxco-pq-chain KxcoChain instance — enables on-chain audit checkpointing. */
  chain?: AuditChainClient
  /** Anchor a checkpoint every N entries (default: 100). Ignored when chain is absent. */
  checkpointEvery?: number
  /** Institution kid used to tag the anchor. Derived from keypair if omitted. */
  institutionKid?: string
  /**
   * Sign once per sealed run instead of once per entry (default: false).
   *
   * Every entry is still hash-chained, which is what detects an edit, a
   * removal, a reorder or an insertion. The signature binds the run to the
   * key. Measured on ML-DSA-65: per-entry signing runs at a few hundred
   * entries per second and ~4.8KB per entry; sealing runs at tens of thousands
   * per second and ~370 bytes. Use it wherever entry volume is high enough
   * that a signature per entry does not fit, such as agent tool calls.
   *
   * The tradeoff: a single entry can no longer be verified in isolation, and
   * entries written since the last seal are chained but unsigned.
   */
  sealed?: boolean
}

/**
 * In-memory tamper-evident audit log.
 *
 * Every entry is SHA-256 hash-chained to its predecessor, and signed with
 * ML-DSA-65 either per entry or, with `sealed: true`, once per run.
 * `verify()` replays the entire chain — any gap, reorder, or edit breaks either
 * the chain or a signature.
 *
 * Appending costs the same on a log of ten entries and a log of ten million:
 * a new entry needs the previous entry's hash, never the log. Concurrent
 * `append()` calls are serialised internally, so two in flight together cannot
 * take the same seq.
 */
export declare class AuditLog {
  constructor(options: AuditLogOptions)

  /** Append a signed, hash-chained entry. Returns the created entry. */
  append(operation: string, metadata?: Record<string, unknown>): Promise<AuditEntry>

  /**
   * Verify the full hash chain, plus every entry's signature on a classic log
   * or every seal on a sealed one.
   */
  /**
   * Replay the log and check every signature.
   *
   * Pass one key for a log signed by one key. Pass several for a log that
   * outlived a key rotation: each record is checked against the key its `kid`
   * names, and records written before 1.4.0 carry no kid and are checked
   * against each key in turn.
   *
   * A record naming a key that was not supplied is a failure that says so,
   * rather than a generic invalid signature.
   */
  verify(
    publicKey: Uint8Array | Buffer | Array<Uint8Array | Buffer>,
  ): Promise<AuditVerifyResult>

  /** The kid of the key this log signs with. */
  readonly signingKid: string

  /**
   * Sign everything appended since the last seal, as one run. Returns the seal,
   * or null when nothing is unsealed. Throws unless the log was constructed
   * with `sealed: true`. Anchors the root when a chain client is configured.
   */
  seal(): Promise<AuditSeal | null>

  /** Every seal this log holds, oldest first. */
  seals(): Promise<AuditSeal[]>

  /** Entries appended since the last seal. Always 0 on a classic log. */
  unsealedCount(): Promise<number>

  /** True when this log signs per run rather than per entry. */
  readonly sealed: boolean

  /**
   * Every entry as an array. Holds the whole log in memory by definition; on a
   * large log prefer `stream()`.
   */
  export(): Promise<AuditEntry[]>

  /** Every entry, in seq order, one at a time. Memory is bounded by one entry. */
  stream(): AsyncIterableIterator<AuditEntry>
}

export interface FileAuditLogOptions extends AuditLogOptions {
  /**
   * Path to the append-only NDJSON file. Created on first write if absent.
   * On a sealed log the seals are written to `<path>.seals`, so a reader that
   * knows only about entries is unaffected.
   */
  path: string
  /**
   * Release the write handle after this many ms without a write (default:
   * 2000). A busy log never goes idle and keeps the handle; a short-lived one
   * hands the descriptor back on its own, so a missed `close()` costs nothing.
   */
  idleReleaseMs?: number
}

/**
 * File-backed audit log. Entries are stored as newline-delimited JSON.
 * The file is strictly append-only — entries are never modified after writing.
 */
export declare class FileAuditLog extends AuditLog {
  constructor(options: FileAuditLogOptions)

  /**
   * Release the write handle. Safe to call more than once. Not required — the
   * handle is released on idle — but call it for a deterministic hand-back.
   * Throws if another writer has touched the file.
   */
  close(): Promise<void>

  /**
   * Throw unless the entry file is the size this instance left it. Runs on
   * every seal and on close; call it directly to check at any other point.
   */
  assertSoleWriter(): Promise<void>
}

export class KxcoPqAuditError extends Error {
  name: 'KxcoPqAuditError'
}
