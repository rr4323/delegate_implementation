# Delegate Feature POC

A working implementation of the scope defined in `../Delegate POC.md`: a
Django control plane, a Celery-worker-based `bp-agent` stand-in, and a Redis
broker/stream backend, wired together to exercise the real mTLS registration
flow and the chunked ZIP transfer protocol from `../Delegate Design.md`.

## What's real here

- **mTLS**: a real local CA (`control_plane/delegates/ca.py`, using the
  `cryptography` library) issues a client cert per delegate after
  registration-token validation, and a real server cert for the control
  plane's restart gateway. The restart channel (`agent_manager/agent_manager.py`
  -> `control_plane/delegates/management/commands/restart_gateway.py`) is
  opened *outbound* by `agent_manager`, as in the design, and is a genuine TLS
  handshake with
  `ssl.CERT_REQUIRED`, not a mock. The delegate's certificate CN is its actual
  `delegate_id` (set at registration, before signing --
  `control_plane/delegates/views.py`). `agent_manager` runs on the delegate's
  machine and presents that same delegate cert, and the restart gateway checks
  the `HELLO` message against the TLS-verified peer cert (and that the
  delegate isn't revoked) before trusting it -- a connection can't claim a
  different delegate's id just by sending it in the message.
- **Chunked transfer protocol**: `shared/delegate_protocol/chunked_transfer.py`
  implements DATA_START/DATA_CHUNK/DATA_END, sequence-number duplicate
  detection, checksum + size validation, and is used in both directions
  (control plane -> worker for the input workspace, worker -> control plane
  for output).
- **Recreate-from-start recovery**: `worker/worker_app/tasks.py`'s
  `_receive_workspace` discards and re-issues `DATA_REQUEST` with a fresh
  `transfer_id` on any timeout/validation failure, exactly as specified.
- **Tenant isolation check**: the dispatcher
  (`control_plane/delegates/management/commands/stream_dispatcher.py`)
  validates delegate ownership + tenant match before responding to any
  `DATA_REQUEST`.
- **VM vs. Kubernetes parity**: `worker_vm` and `worker_k8s_sim` in
  `docker-compose.yml` run the identical image; `worker/k8s-deployment.yaml`
  shows what a real K8s deployment of the same image looks like.
- **Event-driven execution discovery**: the dispatcher does not poll the
  database for new executions. `worker/worker_app/tasks.py` registers a
  Celery `task_prerun` signal (`_prepare_execution`) that runs the whole
  request-data/reconstruct-workspace phase -- including publishing an
  `EXECUTION_STARTED` event naming all four of that execution's streams -- to
  the single global `global:execution_events` stream *before* `execute_task`'s
  body runs at all; the body only runs `task_executor` against an
  already-prepared workspace. `stream_dispatcher.py`'s `Command.handle()` just
  blocks on `XREAD` against that one global stream and spawns a parallel
  per-execution watcher thread in reaction to each announcement;
  `shared/delegate_protocol/streams.py` is the one place the
  `delegate:{delegate_id}:execution:{id}:*` naming convention is defined, so both sides can never
  drift apart on it.
- **Requesting a specific file, not just the whole workspace**: `DATA_REQUEST`
  carries a `requested_file` field (default `"*"` for the whole workspace fixture).
  `create_execution`'s API accepts an optional `file_name`, threaded through
  Celery to `_prepare_execution`, which puts it on the request; the
  dispatcher's `_handle_data_request` zips only that one file
  (`zip_single_file_to_bytes`, with a path-traversal guard since `file_name`
  is attacker-influenceable input) instead of the whole fixture directory. A
  request for a file that doesn't exist is audited as
  `DATA_REQUEST_FILE_NOT_FOUND` and gets no response at all -- the worker
  times out and retries via the normal recreate-from-start path, eventually
  reporting `TRANSFER_FAILED` rather than hanging.
- **Stream cleanup after completion**: once `watch_execution` observes an
  execution reach a terminal status (or gives up after `max_lifetime_seconds`),
  it deletes that execution's four streams (`_cleanup_execution_streams`) and
  records a `STREAMS_CLEANED` audit event. Deliberately done on the control
  plane's side, not the worker's: the worker finishing its own
  `_send_output`/status-publish calls doesn't mean the dispatcher has actually
  *read* those messages yet, so having the worker delete its own streams right
  after publishing to them would race the dispatcher's consumption of the
  final message(s). The dispatcher only reaches "terminal" after it has
  already processed everything in that batch, so it's the only side that can
  safely delete without risking data loss.

## Findings from actually running this

Two real, non-obvious things turned up while getting the happy path and the
failure-recovery scenario working end to end -- both are the kind of finding
the POC exists to surface, per `../Delegate POC.md` Section 7:

- **Celery + Redis broker `visibility_timeout` defaults to 3600s.** With
  `task_acks_late=True` (needed so a killed worker's in-flight task gets
  redelivered rather than silently dropped), the default means a task whose
  worker died mid-transfer stays invisible to every other worker for up to an
  hour before Celery's own redelivery mechanism kicks in -- effectively
  stalling recreate-from-start recovery. Fixed in
  `worker/worker_app/celery_app.py` by setting
  `broker_transport_options={"visibility_timeout": 30}`. This is exactly the
  "Celery retry semantics vs. recreate-from-start" risk flagged in
  `../Delegate Implementation Plan.md`'s risk register -- now backed by a
  concrete number instead of a guess.
- **`docker kill` does not trigger `restart: unless-stopped`.** Verified
  against this host's dockerd (29.1.3): an explicit `docker kill`/`docker
  stop` is treated as an intentional operator action and deliberately
  suppresses the restart policy, unlike a spontaneous non-zero exit from
  inside the container. `scripts/kill_mid_transfer_test.py` therefore issues
  `docker start` explicitly after the kill, standing in for what a process
  supervisor or Kubernetes' pod restart would do automatically in a real
  deployment.

## Known simplifications (see `../Delegate POC.md` Section 3/8 for the full list)

- Chunk payloads travel as base64 text fields on the Redis Stream, not raw
  bytes -- simpler code, ~33% size overhead, fine at POC scale.
- The dispatcher uses plain `XREAD` with an in-memory cursor, not Redis
  consumer groups -- both for the global `EXECUTION_STARTED` announcement
  stream and for each execution's four streams. A dispatcher restart re-reads
  the global stream from the beginning (cheap; it's just announcements) but a
  dispatcher that's *down at the exact moment* an announcement fires will
  never see it and that execution's streams will never be watched -- there is
  no DB-polling fallback anymore. Production would want a consumer group (or
  a periodic reconciliation sweep) as a backstop.
- The registration-token issuance endpoint is intentionally unauthenticated
  so the stack self-registers on `docker compose up`; production gates this
  behind an authenticated admin action.
- Redis access control is implemented for the POC's single-node Redis (see
  "Redis access control" below); replicas/Cluster, a managed-Redis user API and
  cert rotation for the Redis path are not covered.
- SQLite (not Postgres/MySQL) backs the Django app.
- No canary-workspace or build-datafile-stream handling -- out of scope per
  the POC document.

## Redis access control

Redis is **TLS-only, client-cert-required and ACL-enforced**
(`redis/redis.conf`, `redis/entrypoint.sh`, `control_plane/delegates/redis_acl.py`).
Three separate layers:

| Layer | Owns | Mechanism |
|---|---|---|
| Identity | who you are | client cert signed by the POC CA; its CN selects the Redis ACL user (`tls-auth-clients-user CN`, Redis >= 8.6). A delegate's CN is its `delegate_id`; the control plane presents a `cp-admin` cert. |
| Authorization | what you may touch | one ACL user per delegate, confined to `~delegate:<id>:*` and `&delegate:<id>:*`, a fixed minimal command list (no `@dangerous`, no `ACL`/`CONFIG`/`KEYS`/`FLUSH*`), and **write-only** access to `global:execution_events` |
| Lifecycle | whether you are active | the control-plane DB is the source of truth; registration provisions the ACL user, revocation removes it, and the dispatcher reconciles Redis against the DB on start and after any Redis outage |

How it fits together:

- **One key prefix per delegate.** Execution streams are
  `delegate:<id>:execution:<eid>:{events,log,status,output}`
  (`shared/delegate_protocol/streams.py`) *and* the Celery broker uses kombu's
  `global_keyprefix=delegate:<id>:`, so a single static pattern per ACL user
  covers both. The control plane creates a Celery client per delegate
  (`delegates/celery_client.py`) so tasks land only in that delegate's keyspace.
- **Bootstrap order.** Redis needs its server cert to boot, so a one-shot
  `pki_init` service runs `manage.py init_ca` (root CA, Redis server cert,
  `cp-admin` client cert) before Redis starts. `redis/entrypoint.sh` seeds
  `/data/users.acl` with `default` **off** and `cp-admin` only.
- **Announcements are hints, not trust.** Delegates may `XADD` (never `XREAD`)
  the global stream, so its contents are untrusted. The dispatcher derives
  every stream name it reads from the execution's assigned delegate in the DB,
  and audits (`ANNOUNCEMENT_STREAM_MISMATCH`) any announcement that names
  something else. Because only the assigned delegate can write to its own
  streams, the `delegate_id` on a `DATA_REQUEST` is now backed by Redis, not
  self-asserted.
- **Revocation** (`POST /api/delegates/<id>/revoke/`) fans out, each step
  independent and audited: DB status -> `REVOKED` (no new tasks, ownership
  checks fail); `ACL DELUSER` (Redis terminates that user's open connections,
  including a blocked `XREAD`); `restart_gateway` `POST /disconnect/<id>`
  closes its restart websocket. A cert cannot be revoked mid-lifetime by
  Redis, so the ACL is the real control and the 1-day cert validity is the
  backstop.

### Verified findings (Redis 8.6.6)

Checked by `scripts/redis_acl_test.py` and by hand against `redis:8.6`:

- A connection with no client cert, or with a self-signed cert claiming a
  delegate's CN, is rejected at the TLS handshake.
- **A cert whose CN has no ACL user connects as `default`**, not as nobody:
  `default` must be off (seeded in the aclfile). With it off, every command
  returns `Authentication required`.
- **`nopass` users can be impersonated.** A delegate holding *any* valid cert
  could send `AUTH <other user> x` and become that user (confirmed: it wrote to
  another delegate's keys). Every ACL user, including `cp-admin`, therefore has
  a random password that is never stored or handed out; the cert -> user
  mapping needs no password. `AUTH` with a wrong password is refused.
- **`ACL SETUSER <u> off` blocks only new logins**; an already-open
  connection keeps working. **`CLIENT KILL USER` or `ACL DELUSER` terminates
  it** (a blocked `XREAD` returns a connection error within ~1.5s). The
  implementation uses `DELUSER`.
- **Celery works under the restricted ACL**, but only with
  `global_keyprefix`, `worker_enable_remote_control=False` and
  `--without-mingle --without-gossip --without-heartbeat` (pidbox/mingle/gossip
  use pub/sub and broadcast keys outside a delegate's keyspace). The command
  list in `redis_acl.py` was found by restricting a user and reading `ACL LOG`
  denials; kombu needs `set`, `get`, `evalsha`, `script|load` and
  `zrevrangebyscore` beyond the obvious list/hash/set commands.
- **`ACL SAVE` needs the redis user to own `/data`.** It writes a temp file
  next to the aclfile as the unprivileged user; with a root-owned aclfile on a
  bind mount it fails with "Permission denied" and ACLs stay memory-only.
  `redis/entrypoint.sh` chowns `/data`. If it does fail, the control plane logs
  a warning and the dispatcher's reconcile rebuilds users from the DB.
- **Redis restarts used to kill the dispatcher.** It now retries on connection
  loss (also per-execution watchers), re-runs the ACL reconcile once Redis is
  back, and `dispatcher`/`restart_gateway` have `restart: unless-stopped`.
- **Images baked in dev secrets.** `COPY control_plane /app` copied
  `control_plane/ca/ca.key` and the dev SQLite DB into the image, and named
  volumes are seeded from image contents on first mount -- so every container
  started with a stale CA and stale delegates. Fixed with a `.dockerignore`
  (`native-run`, `local-run`, `control_plane/{ca,db,media}`, venvs).
- **Celery's own broker keys are a separate attack surface from the protocol
  streams, and need their own test.** A queued task is a plain Redis *list* at
  `delegate:<id>:<queue-name>` (confirmed by inspecting a live queue), plus a
  `_kombu.binding.<queue-name>` *set* -- neither is a `delegate:*:execution:*`
  stream, so `redis_acl_test.py` never touched them. Verified separately
  (`scripts/rogue_task_execution_test.py`): a rogue delegate's own valid cert
  can `LRANGE`/`BRPOP`/`LPUSH`/`LLEN` its own queue key but is denied on all
  four against another delegate's, its own queue keeps working throughout,
  and revocation removes queue access the same as it removes stream access.

### Known limits of this implementation

- Single-node Redis. ACLs are per node and not replicated: replicas/Cluster
  need each change applied on every node; managed Redis (e.g. ElastiCache) uses
  its own user API instead of `ACL SETUSER`.
- No cert rotation for the Redis path; delegate certs are 1 day, so a stack
  left down for more than a day needs its worker cert volumes deleted to
  re-register. The Redis server and `cp-admin` certs are valid 10 years.
- `restart_gateway` and the HTTP API are still not on the Redis identity
  (`/api/*` is unauthenticated, as before).
- A delegate can append junk to its *own* streams and to the global stream;
  the dispatcher validates content, and the global stream carries only hints.
- Any delegate can flood `global:execution_events` (write-only, but shared);
  a per-delegate announcement stream would remove that.

## Running it

```sh
cd poc
docker compose up --build
```

This starts Redis, the Django control plane (`:18000`), the stream
dispatcher, `restart_gateway` (mTLS websocket on `:18765`, HTTP control API on
`:18766`), two Celery workers (`worker_vm`, `worker_k8s_sim`) that
self-register against tenant `tenant-demo` on startup, and one `agent_manager`
sidecar per worker that dials out to the gateway.

Watch `docker compose logs -f worker_vm` to see registration, DATA_REQUEST,
chunked transfer, execution, and output-send happen in real time.

### Smoke test (happy path)

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r scripts/requirements.txt
python scripts/e2e_smoke_test.py
```

### Tenant isolation probe (Goal 7)

```sh
python scripts/cross_tenant_isolation_test.py
```

Registers an attacker delegate under another tenant and, with its own real
cert, tries to forge a `DATA_REQUEST` onto the victim's stream; Redis refuses
the write and the victim's execution still completes.

### Redis identity, scope and revocation (Goal 8)

```sh
python scripts/redis_acl_test.py
```

Registers an attacker and a victim delegate and attacks Redis with real certs:
no/rogue client cert, out-of-scope reads/writes, dangerous commands, `AUTH`
impersonation, a forged `EXECUTION_STARTED`, and revocation of both new and
already-open connections (a blocked `XREAD` must die within seconds). Exits
non-zero on any failure. Scripts read `CONTROL_PLANE_URL`, `REDIS_HOST` and
`REDIS_PORT` (defaults `localhost:18000` / `localhost:16379`); the Redis host
port serves TLS, so plain `redis-cli` needs `--tls --cacert ... --cert ... --key ...`.

### Task-queue isolation (Celery broker keys, complements Goal 8)

```sh
python scripts/rogue_task_execution_test.py
```

`redis_acl_test.py` covers the delegate protocol's own streams; this covers
Celery's separate broker keys (a queued task is a Redis list at
`delegate:<id>:<queue-name>`, plus a `_kombu.binding.<queue-name>` set --
neither is a protocol stream). Registers a victim and a rogue delegate (no
worker needs to be running), lets the control plane enqueue a real task for
the victim, then has the rogue attack that queue key directly:
read/steal (`LRANGE`/`BRPOP`), inject a forged task (`LPUSH`), and probe its
existence (`LLEN`) -- all must be denied, while the rogue's own queue keeps
working and the victim's message stays untouched. Finishes by revoking both
test delegates and confirming the revoked one loses its own queue access too.

### Kill-mid-transfer / recreate-from-start (Goal 3)

```sh
python scripts/kill_mid_transfer_test.py
```

This generates a ~200MB fixture on first run, starts a transfer, kills the
`worker_vm` container mid-flight with `docker kill`, and confirms the
execution still completes after Docker restarts the container and the
worker re-registers using its persisted identity (reused, not re-issued)
and retransmits the workspace from scratch.

### Agent restart (Goal 6)

```sh
curl -X POST http://localhost:18766/restart/<delegate_id>
```

(`<delegate_id>` from a `DELEGATE_REGISTERED` audit event --
`curl http://localhost:18000/api/audit-events/`.) Watch
`docker compose logs -f agent_manager_vm worker_vm` -- the gateway pushes
RESTART down the delegate's `agent_manager` connection, `agent_manager`
restarts the `worker_vm` container, and it comes back reusing its existing
identity and cert rather than re-registering. (`agent_manager` mounts the
docker socket to restart a sibling container; on a real VM it would use
systemd.)

### Inspecting state

- `curl http://localhost:18000/api/audit-events/` -- full audit trail.
- `curl http://localhost:18000/api/executions/<execution_id>/` -- status,
  transfer attempts, logs, output checksum.
- `curl http://localhost:18765` won't work directly (it's the mTLS
  websocket port); `curl http://localhost:18766/connected` lists which
  delegates' `agent_manager`s currently hold an open restart-channel
  connection.
