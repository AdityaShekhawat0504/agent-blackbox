## Tamper detection (1000 attacks each, seed 11)

| Attack | SHA-256 chain | HMAC chain | HMAC + anchored head |
|---|---:|---:|---:|
| Edit one event | 100% | 100% | 100% |
| Delete an event | 100% | 100% | 100% |
| Insert a forged event | 100% | 100% | 100% |
| Swap two events | 100% | 100% | 100% |
| Cut off the end of the log | 0% | 0% | 100% |
| Edit a decision and recompute all hashes | 0% | 100% | 100% |

Truncated logs still verify as a valid chain, but 100% of them are flagged as incomplete because the closing `run_end` event is missing.

## Recording overhead

| Metric | Value |
|---|---:|
| Append, no fsync | 43.5 µs/event |
| Append, fsync per event | 259.9 µs/event |
| Verify | 41,319 events/s |
| Size | 392 bytes/event |

## Pseudonymisation (300 synthetic samples per type, seed 5)

| Type | Detected |
|---|---:|
| EMAIL | 100% |
| IBAN | 100% |
| CARD | 100% |
| PHONE (international) | 100% |
| PHONE (national, no +) | 0% |
| False positives on 1400 hard negatives | 0.2% |

