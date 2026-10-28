# Sample runs

Recorded by `blackbox demo`: the refund agent with model v1 (`v1/`) and with the regressed v2 (`v2/`).
The chains use the HMAC key `demo-key` (a real deployment keeps its key in a secrets manager):

```bash
blackbox verify docs/sample-runs --key demo-key
blackbox diff docs/sample-runs/v1/urgent-small-refund.jsonl docs/sample-runs/v2/urgent-small-refund.jsonl
```
