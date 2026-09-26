# Phase 2 — workspace-personal API contract

Apply `db/migrations/20260925_personal_sync_api.sql` after the existing Phase 2B
migration before using the new endpoints. The migration is additive and leaves
all existing timer values in place. It assumes the live `workspaces` table has
the `shared_mode_enabled` boolean already used by `/workspace`.

All calls use the existing Bearer access token. Identity and workspace are
resolved from the authenticated user in a single SQL transaction. A disabled
account, a missing workspace, a foreign UUID, a shared UUID, and an archived
timer cannot be used as a personal sync target.

## Read

`GET /timers/personal` (existing): returns `{ timers: [...] }` for the caller's
current workspace, `is_shared=false`, `record_status='active'`, and
`archived_at IS NULL`. Every row includes `sync_revision` (old rows start at 0).
It is a current snapshot, not an outbox acknowledgement.

## Full-state create/update

`PUT /timers/personal/:id` where `:id` is a client-generated UUID:

```json
{
  "dataMode": "workspace-personal",
  "mutationId": "00000000-0000-4000-8000-000000000101",
  "expectedRevision": 0,
  "name": "Work",
  "type": "up",
  "targetMinutes": 5,
  "isPay": false,
  "status": "idle",
  "endsAt": null,
  "endedAt": null,
  "durationMs": null,
  "accumulatedMs": 0,
  "pausedCount": 0
}
```

The request is a **complete canonical snapshot**. All fields shown above
except nullable timestamps/duration are required; `endsAt` is required for
`status='running'`. `isShared:false` may be supplied, but true is rejected.
`status='completed'` is valid only for countdown. `targetMinutes` is finite and
positive for both types. `type` and `targetMinutes` cannot change after
creation. `record_status`, owner, workspace, and creator cannot be supplied.

For a new UUID use `expectedRevision:0`; for an existing row use its current
`sync_revision`. A successful mutation increases the revision by one. Response:
`201` for insert, `200` for update or exact retry, with
`{ success, created, duplicate, timer }`. A retry must reuse the **same**
`mutationId`, expected revision, and state. An exact immediate retry returns
`duplicate:true` without writing. An old retry after a newer mutation gets
`409`; it never overwrites the newer state. A UUID owned by another account,
workspace, or shared mode gets `403`. Deleted/archived records get `409`.

The server does not keep an unlimited request log. If another mutation has
already advanced the revision, an older retry returns `409` even if that older
mutation succeeded before its response was lost. The client must resolve the
latest server state before submitting a new mutation.

## Soft delete

`DELETE /timers/personal/:id` with JSON body:

```json
{
  "dataMode": "workspace-personal",
  "mutationId": "00000000-0000-4000-8000-000000000102",
  "expectedRevision": 1
}
```

The first delete requires the current revision and changes only
`record_status` to `deleted`. A repeated delete by the same account/workspace
returns `200` with `{ success, duplicate, timer }` without changing the row.
Other accounts get `403`, archived rows get `409`, missing IDs get `404`.
The server does **not** create a tombstone for an ID that never existed; Phase 3
must keep create/update/delete operations for the same timer in order.

## Existing frontend and older API

The current frontend still uses `POST /timers`, `PATCH /timers/:id`, and
`DELETE /timers/:id`. They retain their response shapes and behavior. New
personal sync uses the separate endpoints; legacy PATCH/DELETE advance the
same revision so a stale sync cannot overwrite them. New legacy POST requests
need a positive target, and new shared POST requests need shared mode enabled.
Closing shared mode does not hide or freeze existing shared timers.

The old PATCH route has no `expectedRevision`. It can still write after a new
sync snapshot for the **same** timer; the revision then advances, but it cannot
retroactively prevent that legacy write. Phase 3/4 must ensure a given
workspace-personal timer is written through one path during the planned
cutover. Do not dual-write it through both routes.

The current frontend sends non-shared timers through legacy POST even for
signed-in users with **no workspace**. Preserving that live client behavior
means legacy records with `workspace_id=NULL` can still be created; these are
not valid workspace-personal sync records. Explicit `dataMode` is rejected on
legacy POST, including `standalone`. Phase 4 must stop sending standalone
timers at all. No existing localStorage timer is migrated here.

The Phase 3 outbox must bind operations to account/workspace, persist each
stable mutation UUID and revision, send per-timer operations in order, and
resolve `409` before attempting a newer write. It must never enqueue
standalone or shared timer operations. This phase changes no frontend code,
auth/refresh/socket flow, or Telegram scheduling.
