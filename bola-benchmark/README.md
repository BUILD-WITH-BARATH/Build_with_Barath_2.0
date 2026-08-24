# BOLA graph benchmark

This is a minimal reproducible, **synthetic** benchmark for an API object-access detector.

## Run

From this directory, use the bundled Python runtime:

```powershell
& 'C:\Users\suriy\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' benchmark.py
& 'C:\Users\suriy\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m uvicorn app:app --port 8000
```

The benchmark writes `results/events.csv`, `results/metrics.json`, and `results/warmup_curve.csv`.

## Manual demo

Start the server, open `http://127.0.0.1:8000/docs`, and try `GET /records/{record_id}` with the `X-Subject` header:

* `dr_singh`, record `17`: an allowed assigned-access decision with an explanation.
* `support_amy`, record `17`: an allowed delegated-access decision showing the ticket, approver, expiry, and seconds remaining.
* `attacker`, record `17`: a denied decision that explains the missing permission. Repeat four different record IDs to receive a behavioral BOLA block with its signals.
* `GET /audit-events` with `X-Subject: security_admin`: the last 100 allow/deny/block decisions. This endpoint is demo-only; a production implementation would use the organisation's existing security-admin identity and audit storage.

## Design and safety claims

* **Authoritative authorization comes first.** Owners, medical assignments, and explicit time-bound delegated grants are the only allowed edges. A learned graph never grants access.
* **Cold start is observe-only for authorized access.** A valid first access creates a graph edge but is not blocked because it is unseen.
* **Fail-safe behavior:** unauthorized access is denied by the API; it is escalated to a detector block after four distinct denials in 30 seconds or three sequential-ID transitions. Each decision is recorded in a local audit log and includes human-readable reasons. In production, wire a block to your gateway/rate limiter and retain audit logs.
* **Poisoning resistance:** denied events never create graph edges.
* **Caveat:** all efficacy numbers are from deterministic synthetic traffic, not production data. The ASGI latency excludes network, TLS, reverse proxy, and external-policy-service time.

## Assumption to confirm

The implemented detector treats the graph as behavioral telemetry plus a strict authorization policy. If your intended proposal instead lets learned graph relationships authorize access, confirm that explicitly: it needs a much stronger identity, expiry, revocation, and approval model to remain safe.
