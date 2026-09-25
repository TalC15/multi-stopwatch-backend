import test from "node:test";
import assert from "node:assert/strict";
import { fixture, ids, timer, row, close, change } from "./support/database.js";

const fromNow = (ms) => new Date(Date.now() + ms).toISOString();
const expectRejected = async (fn, code) => assert.rejects(fn, new RegExp(code));

test("manager closes only own worker, preserves all personal history and revokes sessions", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { status: "paused", accumulated_ms: 14000 });
  await timer(db, ids.deleted, { status: "paused", accumulated_ms: 9000, record_status: "deleted" });
  await timer(db, ids.shared, { is_shared: true, status: "running" });
  await timer(db, ids.standalone, { workspace_id: null, status: "paused" });

  await expectRejected(() => close(db, ids.outsider), "KEEPTIMER_WORKER_FORBIDDEN");
  assert.equal((await row(db, "users", ids.worker)).disabled_at, null);
  const result = await close(db);
  assert.equal(result.already_disabled, false);
  assert.deepEqual(result.archived_timer_ids.sort(), [ids.personal, ids.deleted].sort());
  const worker = await row(db, "users", ids.worker);
  assert.equal(worker.workspace_id, ids.company);
  assert.ok(worker.disabled_at);
  assert.ok((await row(db, "sessions", ids.session)).revoked_at);
  const personal = await row(db, "timers", ids.personal);
  const deleted = await row(db, "timers", ids.deleted);
  assert.equal(Number(personal.accumulated_ms), 14000);
  assert.equal(personal.status, "paused");
  assert.equal(deleted.record_status, "deleted");
  assert.equal(Number(deleted.accumulated_ms), 9000);
  assert.ok(personal.archived_at && deleted.archived_at);
  assert.equal((await row(db, "timers", ids.shared)).archived_at, null);
  assert.equal((await row(db, "timers", ids.shared)).created_by, ids.worker);
  assert.equal((await row(db, "timers", ids.standalone)).archived_at, null);

  const repeat = await close(db);
  assert.equal(repeat.already_disabled, true);
  assert.deepEqual(repeat.archived_timer_ids.sort(), [ids.personal, ids.deleted].sort());
  assert.equal((await row(db, "timers", ids.personal)).archived_at.getTime(), personal.archived_at.getTime());
  assert.equal((await row(db, "timers", ids.deleted)).accumulated_ms, deleted.accumulated_ms);
});

test("active up timer can run beyond its target, including multiple pause/resume cycles", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { target_minutes: 1, accumulated_ms: 0,
    ends_at: null, status: "idle" });
  await change(db, ids.worker, ids.personal, { status: "running", ends_at: fromNow(60000) });
  const firstStart = (await row(db, "timers", ids.personal)).started_at;
  await change(db, ids.worker, ids.personal, { status: "paused", accumulated_ms: 20000, paused_count: 1 });
  await change(db, ids.worker, ids.personal, { status: "running", ends_at: fromNow(40000) });
  await change(db, ids.worker, ids.personal, { status: "paused", accumulated_ms: 130000, paused_count: 2 });
  // Third resume: 130s accumulated, 60s target; ends_at is 70s in the past.
  await change(db, ids.worker, ids.personal, { status: "running", ends_at: fromNow(-70000) });
  await close(db);
  const saved = await row(db, "timers", ids.personal);
  assert.equal(saved.status, "paused");
  assert.equal(saved.archive_elapsed_uncertain, false);
  assert.ok(Number(saved.accumulated_ms) >= 130000);
  assert.ok(Number(saved.accumulated_ms) < 160000);
  assert.equal(saved.duration_ms, null);
  assert.equal(saved.paused_count, 2);
  assert.equal(saved.started_at.getTime(), firstStart.getTime());
});

test("expired countdown caps elapsed at target and keeps record_status", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { type: "down", target_minutes: 2,
    accumulated_ms: 25000, ends_at: fromNow(-20000) });
  await timer(db, ids.deleted, { type: "down", status: "completed",
    target_minutes: 1, duration_ms: 60000, accumulated_ms: 60000,
    ended_at: fromNow(-10000), record_status: "deleted" });
  await close(db);
  const saved = await row(db, "timers", ids.personal);
  assert.equal(saved.status, "completed");
  assert.equal(Number(saved.accumulated_ms), 120000);
  assert.equal(Number(saved.duration_ms), 120000);
  assert.equal(saved.record_status, "active");
  assert.equal(saved.archive_elapsed_uncertain, false);
  const completed = await row(db, "timers", ids.deleted);
  assert.equal(completed.status, "completed");
  assert.equal(completed.record_status, "deleted");
  assert.equal(Number(completed.duration_ms), 60000);
  assert.equal(Number(completed.accumulated_ms), 60000);
});

test("missing or inconsistent time does not block closure or invent elapsed time", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { target_minutes: null, ends_at: null,
    accumulated_ms: 33000, duration_ms: 35000 });
  await timer(db, ids.deleted, { target_minutes: 1, ends_at: fromNow(100000),
    accumulated_ms: 45000, duration_ms: 55000, record_status: "deleted" });
  const lowCalculation = "00000000-0000-4000-8000-000000000013";
  await timer(db, lowCalculation, { target_minutes: 1, ends_at: fromNow(45000),
    accumulated_ms: 45000, duration_ms: null });
  await close(db);
  for (const [id, accumulation, duration] of [
    [ids.personal, "33000", "35000"], [ids.deleted, "45000", "55000"],
    [lowCalculation, "45000", null],
  ]) {
    const saved = await row(db, "timers", id);
    assert.equal(saved.status, "paused");
    assert.equal(Number(saved.accumulated_ms), Number(accumulation));
    assert.equal(saved.duration_ms == null ? null : Number(saved.duration_ms), duration == null ? null : Number(duration));
    assert.equal(saved.archive_elapsed_uncertain, true);
    assert.ok(saved.archived_at);
  }
  assert.ok((await row(db, "users", ids.worker)).disabled_at);
});

test("old device cannot insert, write, delete, reassign, or reactivate company timers", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { ends_at: fromNow(59000) });
  await timer(db, ids.shared, { is_shared: true });
  await close(db);
  await expectRejected(() => change(db, ids.worker, ids.shared, { is_pay: true }), "KEEPTIMER_ACCOUNT_DISABLED");
  await expectRejected(() => change(db, ids.worker, ids.personal, { status: "running" }), "KEEPTIMER_ACCOUNT_DISABLED");
  await expectRejected(() => change(db, ids.manager, ids.personal, { status: "running" }), "KEEPTIMER_TIMER_NOT_ACTIVE");
  await expectRejected(() => db.query("UPDATE timers SET archived_at=NULL,status='running' WHERE id=$1", [ids.personal]), "KEEPTIMER_ARCHIVED_TIMER_IMMUTABLE");
  await expectRejected(() => db.query("DELETE FROM timers WHERE id=$1", [ids.personal]), "KEEPTIMER_COMPANY_TIMER_DELETE_BLOCKED");
  await expectRejected(() => timer(db, ids.deleted, {}), "KEEPTIMER_ACCOUNT_DISABLED");
  await expectRejected(() => db.query("UPDATE users SET workspace_id=$1 WHERE id=$2", [ids.otherCompany, ids.worker]), "KEEPTIMER_ACCOUNT_DISABLED");
  await expectRejected(() => db.query("UPDATE users SET disabled_at=NULL WHERE id=$1", [ids.worker]), "KEEPTIMER_ACCOUNT_REACTIVATION_BLOCKED");
  await expectRejected(() => db.query("UPDATE users SET telegram_chat_id='late' WHERE id=$1", [ids.worker]), "KEEPTIMER_ACCOUNT_DISABLED");
  assert.equal((await row(db, "timers", ids.shared)).status, "running");
});

test("active account can still update shared timer using atomic DB actor check", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.shared, { is_shared: true, status: "running", paused_count: 2 });
  await timer(db, ids.personal, { status: "idle" });
  await expectRejected(() => timer(db, ids.deleted, { is_shared: null }), "KEEPTIMER_TIMER_SHARING_REQUIRED");
  await expectRejected(() => db.query("UPDATE timers SET created_by=$1 WHERE id=$2", [ids.manager, ids.shared]), "KEEPTIMER_SHARED_SCOPE_IMMUTABLE");
  await expectRejected(() => db.query("UPDATE timers SET workspace_id=$1 WHERE id=$2", [ids.otherCompany, ids.shared]), "KEEPTIMER_SHARED_SCOPE_IMMUTABLE");
  await expectRejected(() => change(db, ids.outsider, ids.shared, { status: "paused" }), "KEEPTIMER_TIMER_FORBIDDEN");
  const saved = await change(db, ids.manager, ids.shared, { status: "paused", paused_count: 100 });
  assert.equal(saved.paused_count, 3);
  assert.equal((await row(db, "timers", ids.shared)).status, "paused");
  assert.equal((await change(db, ids.superadmin, ids.personal, { status: "paused" })).status, "paused");
  await expectRejected(() => db.query("UPDATE timers SET is_shared=true WHERE id=$1", [ids.personal]), "KEEPTIMER_TIMER_MODE_IMMUTABLE");
  await expectRejected(() => change(db, ids.manager, ids.shared, { record_status: "completed" }), "KEEPTIMER_TIMER_INVALID_UPDATE");
  await expectRejected(() => change(db, ids.manager, ids.shared, { record_status: null }), "KEEPTIMER_TIMER_INVALID_UPDATE");
});

test("superadmin may close a company worker but manager accounts remain protected", async (t) => {
  const db = await fixture(t);
  await expectRejected(() => close(db, ids.superadmin, ids.manager), "KEEPTIMER_WORKER_FORBIDDEN");
  await expectRejected(() => db.query("DELETE FROM users WHERE id=$1", [ids.manager]), "KEEPTIMER_COMPANY_USER_DELETE_BLOCKED");
  const closed = await close(db, ids.superadmin);
  assert.equal(closed.user_id, ids.worker);
});

test("session creation and refresh updates fail after closure", async (t) => {
  const db = await fixture(t);
  const before = await db.query("SELECT public.keeptimer_refresh_session($1,$2,'hash') AS active", [ids.worker, ids.session]);
  assert.equal(before.rows[0].active, true);
  await close(db);
  const after = await db.query("SELECT public.keeptimer_refresh_session($1,$2,'hash') AS active", [ids.worker, ids.session]);
  assert.equal(after.rows[0].active, false);
  await expectRejected(() => db.query(
    "INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'late')",
    [ids.personal, ids.worker],
  ), "KEEPTIMER_ACCOUNT_DISABLED");
  await expectRejected(() => db.query(
    "UPDATE sessions SET revoked_at=NULL WHERE id=$1", [ids.session],
  ), "KEEPTIMER_ACCOUNT_DISABLED");
});

test("company history cannot be removed by FK cascades; last manager survives", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal);
  await expectRejected(() => db.query("UPDATE users SET workspace_id=$1 WHERE id=$2", [ids.otherCompany, ids.worker]), "KEEPTIMER_COMPANY_WORKSPACE_IMMUTABLE");
  await expectRejected(() => db.query("DELETE FROM users WHERE id=$1", [ids.worker]), "KEEPTIMER_COMPANY_USER_DELETE_BLOCKED");
  await expectRejected(() => db.query("DELETE FROM workspaces WHERE id=$1", [ids.company]), "KEEPTIMER_WORKSPACE_HISTORY_PROTECTED");
  await expectRejected(() => db.query("UPDATE users SET role='worker' WHERE id=$1", [ids.manager]), "KEEPTIMER_LAST_MANAGER");
  await expectRejected(() => close(db, ids.manager, ids.manager), "KEEPTIMER_SELF_DEACTIVATION_BLOCKED");
  await expectRejected(() => close(db, ids.manager, ids.outsider), "KEEPTIMER_WORKER_FORBIDDEN");
});

test("company worker cannot be promoted into a transferable manager account", async (t) => {
  const db = await fixture(t);
  await db.query("INSERT INTO users(id,username,pin_hash,role,workspace_id) VALUES($1,'manager2','pin','manager',$2)", [ids.secondManager, ids.company]);
  await expectRejected(() => db.query("UPDATE users SET role='manager' WHERE id=$1", [ids.worker]), "KEEPTIMER_COMPANY_ROLE_IMMUTABLE");
  await expectRejected(() => db.query("UPDATE users SET role='superadmin' WHERE id=$1", [ids.worker]), "KEEPTIMER_COMPANY_ROLE_IMMUTABLE");
  await expectRejected(() => db.query("UPDATE users SET role='superadmin' WHERE id=$1", [ids.manager]), "KEEPTIMER_COMPANY_ROLE_IMMUTABLE");
  await expectRejected(() => db.query("UPDATE users SET workspace_id=NULL WHERE id=$1", [ids.manager]), "KEEPTIMER_COMPANY_WORKSPACE_IMMUTABLE");
  await expectRejected(() => db.query("UPDATE users SET workspace_id=$1 WHERE id=$2", [ids.otherCompany, ids.manager]), "KEEPTIMER_COMPANY_WORKSPACE_IMMUTABLE");
  assert.equal((await row(db, "users", ids.worker)).role, "worker");
  assert.equal((await row(db, "users", ids.manager)).workspace_id, ids.company);
});

test("failure inside archive transaction rolls back account closure and session revocation", async (t) => {
  const db = await fixture(t);
  await timer(db, ids.personal, { ends_at: fromNow(55000) });
  await timer(db, ids.deleted, { status: "paused", record_status: "deleted" });
  await db.exec(`ALTER TABLE timers ADD CONSTRAINT test_reject_second_archive
    CHECK (id <> '${ids.deleted}'::uuid OR archived_at IS NULL)`);
  await assert.rejects(() => close(db));
  assert.equal((await row(db, "users", ids.worker)).disabled_at, null);
  assert.equal((await row(db, "sessions", ids.session)).revoked_at, null);
  assert.equal((await row(db, "timers", ids.personal)).archived_at, null);
  assert.equal((await row(db, "timers", ids.deleted)).archived_at, null);
});

test("new RPC functions are inaccessible to anonymous and authenticated roles", async (t) => {
  const db = await fixture(t);
  const { rows } = await db.query(`SELECT has_function_privilege('anon',
    'public.keeptimer_close_company_worker(uuid,uuid)', 'EXECUTE') anon,
    has_function_privilege('authenticated',
    'public.keeptimer_change_timer(uuid,uuid,jsonb,boolean)', 'EXECUTE') authenticated,
    has_function_privilege('service_role',
    'public.keeptimer_close_company_worker(uuid,uuid)', 'EXECUTE') service,
    has_function_privilege('authenticated',
    'public.keeptimer_refresh_session(uuid,uuid,text)', 'EXECUTE') refresh`);
  assert.equal(rows[0].anon, false);
  assert.equal(rows[0].authenticated, false);
  assert.equal(rows[0].service, true);
  assert.equal(rows[0].refresh, false);
});
