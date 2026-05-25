# kxco-pq-audit

[![npm](https://img.shields.io/npm/v/kxco-pq-audit?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-audit)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-audit)](https://socket.dev/npm/package/kxco-pq-audit)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-audit.svg)](https://nodejs.org)

Tamper-evident post-quantum audit log. Every operation produces an ML-DSA-65-signed entry chained to the previous via SHA-256. `verify()` replays the entire log — any gap, reorder, or edit breaks the chain or a signature. Memory and append-only NDJSON file backends.

## Install

```
npm install kxco-pq-audit
```

## Quick start

```js
import { AuditLog } from 'kxco-pq-audit'
import { mlDsa } from 'kxco-post-quantum'

const keypair = mlDsa.ml_dsa65.keygen()
const log = new AuditLog({ keypair })

await log.append('keygen',  { label: 'prod-signing', alg: 'ml-dsa-65' })
await log.append('sign',    { label: 'prod-signing', bytes: 24 })
await log.append('rotate',  { label: 'prod-signing', successor: 'prod-signing-v2' })

const { valid, count } = await log.verify(keypair.publicKey)
// { valid: true, count: 3 }
```

## File-backed log

```js
import { FileAuditLog } from 'kxco-pq-audit'

const log = new FileAuditLog({ keypair, path: './audit.ndjson' })
await log.append('sign', { label: 'prod-key' })

// In a different process:
const log2 = new FileAuditLog({ keypair, path: './audit.ndjson' })
const result = await log2.verify(keypair.publicKey)
// { valid: true, count: 1 }
```

## Entry format

```json
{
  "seq": 0,
  "timestamp": "2026-05-24T07:29:22.000Z",
  "operation": "keygen",
  "metadata": { "label": "prod-signing", "alg": "ml-dsa-65" },
  "prevHash": null,
  "signature": "<base64url ML-DSA-65>"
}
```

`prevHash` is the SHA-256 of the complete previous entry (including its signature). The first entry always has `prevHash: null`. The signing message covers all fields except `signature` itself.

## API

```js
const log = new AuditLog({ keypair })          // or FileAuditLog({ keypair, path })

await log.append(operation, metadata)           // → entry object
await log.verify(publicKey)                     // → { valid, count } | { valid: false, error }
await log.export()                              // → entry[]
```

## Related packages

| Package | Role |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 primitives |
| [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) | HSM-backed key management |
| [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) | Payload attestation |
| [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) | `AuditedHsm` wires HSM + audit automatically |

## Security

Entry signing uses [Noble post-quantum](https://github.com/paulmillr/noble-post-quantum) ML-DSA-65 and [Noble hashes](https://github.com/paulmillr/noble-hashes) SHA-256 — independently audited by Cure53 (2024). The hash chain means a compromised or deleted entry cannot be hidden: any gap breaks verification of every subsequent entry.

To report a vulnerability, open a [private security advisory](https://github.com/JackKXCO/kxco-pq-audit/security/advisories/new) or email **security@kxco.ai**.

## Funding

Maintained by **Shayne Heffernan** and **John Heffernan** at [KXCO by Knightsbridge](https://kxco.ai).

[Knightsbridge Law](https://knightsbridge.law) · [target150.com](https://target150.com) · [livetradingnews.com](https://livetradingnews.com)

## License

Apache-2.0 © 2026 KXCO by Knightsbridge

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
