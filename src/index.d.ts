/// <reference types="node" />

export interface AuditEntry {
  seq:       number
  timestamp: string
  operation: string
  metadata:  Record<string, unknown>
  /** SHA-256 of the previous entry (entire JSON including signature). Null for the first entry. */
  prevHash:  string | null
  /** base64url ML-DSA-65 signature over a canonical representation of all other fields. */
  signature: string
}

export interface AuditVerifySuccess {
  valid: true
  count: number
}

export interface AuditVerifyFailure {
  valid: false
  error: string
}

export type AuditVerifyResult = AuditVerifySuccess | AuditVerifyFailure

export interface AuditLogOptions {
  keypair: {
    publicKey: Uint8Array | Buffer
    secretKey: Uint8Array | Buffer
  }
}

/**
 * In-memory tamper-evident audit log.
 *
 * Each entry is ML-DSA-65-signed and SHA-256 hash-chained to its predecessor.
 * `verify()` replays the entire chain — any gap, reorder, or edit breaks either
 * the chain or a signature.
 */
export declare class AuditLog {
  constructor(options: AuditLogOptions)

  /** Append a signed, hash-chained entry. Returns the created entry. */
  append(operation: string, metadata?: Record<string, unknown>): Promise<AuditEntry>

  /** Verify every entry's signature and the full hash chain. */
  verify(publicKey: Uint8Array | Buffer): Promise<AuditVerifyResult>

  /** Return a copy of all entries. */
  export(): Promise<AuditEntry[]>
}

export interface FileAuditLogOptions extends AuditLogOptions {
  /** Path to the append-only NDJSON file. Created on first write if absent. */
  path: string
}

/**
 * File-backed audit log. Entries are stored as newline-delimited JSON.
 * The file is strictly append-only — entries are never modified after writing.
 */
export declare class FileAuditLog extends AuditLog {
  constructor(options: FileAuditLogOptions)
}

export class KxcoPqAuditError extends Error {
  name: 'KxcoPqAuditError'
}
