export class KxcoPqAuditError extends Error {
  constructor(msg) {
    super(msg)
    this.name = 'KxcoPqAuditError'
  }
}
