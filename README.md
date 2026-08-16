# NetWeave

NetWeave is a self-hosted operations console for volunteer emergency-radio teams. It keeps the incident net, station board, formal traffic queue, relay attempts, and closeout record in one durable local workflow.

## What It Does

- Plans and opens incidents with timezone, frequency, and control operator metadata.
- Canonicalizes station call signs and preserves every check-in session.
- Captures formal traffic with precedence, expiry, idempotency, and immutable transition history.
- Uses expected record versions for atomic claims, release, transfer, and relay acknowledgements.
- Exposes server-rendered dashboard, station board, traffic detail, closeout, and print views.
- Provides JSON API endpoints, SSE events with reconnect cursors, and a polling endpoint.
- Imports station rosters through CSV preview/apply endpoints and exports portable JSON archives.
- Persists every committed state change in a checksummed append-only journal with atomic snapshots.

## Run Locally

```text
go run ./cmd/netweave --listen 127.0.0.1:8080 --data ./data
```

The default storage files are `./data/journal.jsonl` and `./data/snapshot.json`. The server exposes `/healthz` and `/readyz`, and all browser mutations use a CSRF token carried by the local cookie and form/header.

Administrative commands use the same data path:

```text
go run ./cmd/netweave --command verify --data ./data
go run ./cmd/netweave --command snapshot --data ./data
go run ./cmd/netweave --command export --data ./data --incident <incident-id> --output archive.json
```

See [BENZHI_README.md](BENZHI_README.md) for the standard build, Docker, smoke, and regression commands.
