import test from "node:test";
import assert from "node:assert/strict";
import {
  fixture, applyPersonalSyncMigration, ids, timer, row, close, change,
} from "./support/database.js";

const uuid = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const state = (overrides = {}) => ({
  name: "Personal", type: "up", target_minutes: 1, is_pay: false,
  status: "idle", ends_at: null, ended_at: null, duration_ms: null,
  accumulated_ms: 0, paused_count: 0, ...overrides,
});
const put = async (db, actor, id, mutation, revision, snapshot = state()) => {
  const { rows } = await db.query(
    "SELECT public.keeptimer_sync_personal($1,$2,$3,$4,$5::jsonb) AS result",
    [actor, id, mutation, revision, JSON.stringify(snapshot)],
  );
  return rows[0].result;
};
const remove = async (db, actor, id, mutation, revision) => {
  const { rows } = await db.query(
    "SELECT public.keeptimer_delete_personal($1,$2,$3,$4) AS result",
    [actor, id, mutation, revision],
  );
  return rows[0].result;
};

test("client UUID create and exact retry do not duplicate or change a row", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const id = uuid(41), mutation = uuid(42);
  const first = await put(db, ids.worker, id, mutation, 0);
  assert.equal(first.created, true);
  assert.equal(first.timer.sync_revision, 1);
  assert.equal(first.timer.user_id, ids.worker);
  assert.equal(first.timer.workspace_id, ids.company);
  assert.equal(first.timer.created_by, ids.worker);
  assert.equal(first.timer.is_shared, false);

  const replay = await put(db, ids.worker, id, mutation, 0);
  assert.equal(replay.duplicate, true);
  assert.equal(replay.timer.sync_revision, 1);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM timers WHERE id=$1", [id])).rows[0].n, 1);
  await assert.rejects(() => put(db, ids.worker, id, mutation, 0,
    state({ name: "Different request with same mutation ID" })), /KEEPTIMER_SYNC_MUTATION_REUSED/);
});

test("foreign, shared, and no-workspace UUIDs are never reassigned", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const own = uuid(43), foreign = uuid(44), shared = uuid(45), localLegacy = uuid(49);
  await put(db, ids.worker, own, uuid(51), 0);
  await timer(db, shared, { is_shared: true });
  await timer(db, localLegacy, { workspace_id: null });
  await assert.rejects(() => put(db, ids.outsider, own, uuid(52), 0), /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => put(db, ids.worker, shared, uuid(53), 0), /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => put(db, ids.worker, localLegacy, uuid(66), 0),
    /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => remove(db, ids.outsider, own, uuid(54), 1), /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => remove(db, ids.worker, shared, uuid(55), 0), /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => put(db, ids.superadmin, foreign, uuid(56), 0),
    /KEEPTIMER_PERSONAL_WORKSPACE_REQUIRED/);
  assert.equal((await row(db, "timers", own)).user_id, ids.worker);
  assert.equal((await row(db, "timers", shared)).is_shared, true);
});

test("revisions reject stale retries and legacy PATCH advances the revision", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const id = uuid(46), first = state();
  await put(db, ids.worker, id, uuid(57), 0, first);
  const second = state({ name: "Updated", accumulated_ms: 160000,
    status: "running", ends_at: new Date(Date.now() - 100000).toISOString(),
    paused_count: 3 });
  const saved = await put(db, ids.worker, id, uuid(58), 1, second);
  assert.equal(saved.timer.sync_revision, 2);
  assert.equal(saved.timer.status, "running");
  assert.equal((await put(db, ids.worker, id, uuid(58), 1, second)).duplicate, true);

  const third = state({ ...second, name: "Newest", accumulated_ms: 180000 });
  await put(db, ids.worker, id, uuid(59), 2, third);
  await assert.rejects(() => put(db, ids.worker, id, uuid(58), 1, second),
    /KEEPTIMER_SYNC_REVISION_CONFLICT/);
  await assert.rejects(() => put(db, ids.worker, id, uuid(60), 2, second),
    /KEEPTIMER_SYNC_REVISION_CONFLICT/);

  await change(db, ids.worker, id, { is_pay: true });
  const afterLegacy = await row(db, "timers", id);
  assert.equal(afterLegacy.sync_revision, 4);
  assert.equal(afterLegacy.last_sync_mutation_id, null);
  await assert.rejects(() => put(db, ids.worker, id, uuid(61), 3, third),
    /KEEPTIMER_SYNC_REVISION_CONFLICT/);
  assert.equal(afterLegacy.name, "Newest");
});

test("personal deletion is a stable tombstone; archive, foreign data and late create are protected", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const id = uuid(47), mutation = uuid(62);
  await put(db, ids.worker, id, uuid(63), 0);
  await assert.rejects(() => remove(db, ids.worker, id, mutation, 0),
    /KEEPTIMER_SYNC_REVISION_CONFLICT/);
  const removed = await remove(db, ids.worker, id, mutation, 1);
  assert.equal(removed.timer.record_status, "deleted");
  assert.equal(removed.timer.sync_revision, 2);
  assert.equal((await remove(db, ids.worker, id, mutation, 1)).duplicate, true);
  assert.equal((await row(db, "timers", id)).sync_revision, 2);
  await assert.rejects(() => put(db, ids.worker, id, uuid(64), 2), /KEEPTIMER_TIMER_NOT_ACTIVE/);
  await assert.rejects(() => put(db, ids.worker, id, uuid(63), 0), /KEEPTIMER_TIMER_NOT_ACTIVE/);
  await assert.rejects(() => remove(db, ids.outsider, id, mutation, 1), /KEEPTIMER_TIMER_FORBIDDEN/);
  await assert.rejects(() => remove(db, ids.worker, uuid(99), mutation, 0), /KEEPTIMER_TIMER_NOT_FOUND/);

  await close(db);
  const archived = await row(db, "timers", id);
  assert.ok(archived.archived_at);
  assert.equal(archived.record_status, "deleted");
  assert.equal(archived.user_id, ids.worker);
  await assert.rejects(() => remove(db, ids.worker, id, mutation, 1), /KEEPTIMER_ACCOUNT_DISABLED/);
  await assert.rejects(() => put(db, ids.worker, uuid(48), uuid(65), 0), /KEEPTIMER_ACCOUNT_DISABLED/);
});

test("new target and shared-mode rules affect inserts only; count-up continues", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const shared = uuid(70);
  await timer(db, shared, { is_shared: true, type: "down", target_minutes: 1 });
  await db.query("UPDATE workspaces SET shared_mode_enabled=false WHERE id=$1", [ids.company]);
  await assert.rejects(() => timer(db, uuid(71), { is_shared: true }),
    /KEEPTIMER_SHARED_MODE_DISABLED/);
  const oldShared = await change(db, ids.worker, shared, { status: "paused" });
  assert.equal(oldShared.status, "paused");
  await assert.rejects(() => timer(db, uuid(72), { target_minutes: null }),
    /KEEPTIMER_TIMER_TARGET_REQUIRED/);
  await assert.rejects(() => timer(db, uuid(73), { target_minutes: 0 }),
    /KEEPTIMER_TIMER_TARGET_REQUIRED/);
  await assert.rejects(() => timer(db, uuid(83), { target_minutes: "NaN" }),
    /KEEPTIMER_TIMER_TARGET_REQUIRED/);

  const personal = uuid(74);
  await put(db, ids.worker, personal, uuid(75), 0, state({
    status: "running", accumulated_ms: 120000,
    ends_at: new Date(Date.now() - 60000).toISOString(),
  }));
  assert.equal((await row(db, "timers", personal)).status, "running");
  await assert.rejects(() => put(db, ids.worker, uuid(76), uuid(77), 0,
    state({ status: "completed" })), /KEEPTIMER_SYNC_INVALID_STATE/);
  const down = await put(db, ids.worker, uuid(78), uuid(79), 0,
    state({ type: "down", status: "completed", duration_ms: 60000,
      accumulated_ms: 60000 }));
  assert.equal(down.timer.status, "completed");
});

test("old incomplete timer survives additive migration and can still be archived", async t => {
  const db = await fixture(t);
  await timer(db, uuid(80), { target_minutes: null, ends_at: null,
    accumulated_ms: 5000, status: "running" });
  await applyPersonalSyncMigration(db);
  const result = await close(db);
  assert.deepEqual(result.archived_timer_ids, [uuid(80)]);
  const archived = await row(db, "timers", uuid(80));
  assert.equal(archived.accumulated_ms, 5000);
  assert.equal(archived.archive_elapsed_uncertain, true);
  assert.ok(archived.archived_at);
});

test("new security-definer functions are callable only by the backend service role", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  for (const signature of [
    "public.keeptimer_sync_personal(uuid,uuid,uuid,bigint,jsonb)",
    "public.keeptimer_delete_personal(uuid,uuid,uuid,bigint)",
  ]) {
    const result = await db.query(`SELECT
      has_function_privilege('anon',$1,'EXECUTE') AS anon,
      has_function_privilege('authenticated',$1,'EXECUTE') AS authenticated,
      has_function_privilege('service_role',$1,'EXECUTE') AS service`, [signature]);
    assert.deepEqual(result.rows[0], {
      anon: false, authenticated: false, service: true,
    });
  }
});

test("failed sync transaction leaves personal state, revision and mutation marker intact", async t => {
  const db = await fixture(t);
  await applyPersonalSyncMigration(db);
  const id = uuid(81);
  await put(db, ids.worker, id, uuid(82), 0);
  await db.exec(`
    CREATE FUNCTION public.reject_sync_for_test() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'test transaction abort'; END; $$;
    CREATE TRIGGER reject_sync_for_test AFTER UPDATE ON public.timers
      FOR EACH ROW EXECUTE FUNCTION public.reject_sync_for_test();
  `);
  await assert.rejects(() => put(db, ids.worker, id, uuid(83), 1,
    state({ name: "Must not persist" })), /test transaction abort/);
  const after = await row(db, "timers", id);
  assert.equal(after.name, "Personal");
  assert.equal(after.sync_revision, 1);
  assert.equal(after.last_sync_mutation_id, uuid(82));
});
