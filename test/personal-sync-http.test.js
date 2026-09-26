import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { ids } from "./support/database.js";

test("old timer routes remain usable; new personal routes trust the session scope", async () => {
  process.env.JWT_SECRET = "local-phase2-personal-http-test";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-key";
  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(done => reservation.close(done));
  process.env.PORT = String(port);

  const insertCalls = [], syncCalls = [], deleteCalls = [], legacyCalls = [];
  const originalFetch = globalThis.fetch;
  const eq = (url, key) => url.searchParams.get(key)?.replace(/^eq\./, "");
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);
    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }
    const table = url.pathname.split("/").at(-1);
    const method = options.method || request.method || "GET";
    let data;
    if (table === "users") {
      data = eq(url, "role") ? { id: ids.superadmin } :
        { id: ids.worker, role: "worker", workspace_id: ids.company,
          disabled_at: null };
    } else if (table === "sessions") {
      data = { id: ids.session, revoked_at: null };
    } else if (table === "timers" && method === "POST") {
      const inserted = JSON.parse(options.body);
      insertCalls.push(inserted);
      if (inserted.is_shared) {
        return new Response(JSON.stringify({ code: "P0001",
          message: "KEEPTIMER_SHARED_MODE_DISABLED" }),
        { status: 400, headers: { "Content-Type": "application/json" } });
      }
      data = { ...inserted, sync_revision: 0 };
    } else if (table === "timers") {
      data = { id: ids.personal, user_id: ids.worker,
        workspace_id: ids.company, is_shared: false,
        record_status: "active", status: "idle", type: "up" };
    } else if (table === "keeptimer_sync_personal") {
      const args = JSON.parse(options.body);
      syncCalls.push(args);
      const denial = args.p_timer_id === ids.outsider
        ? "KEEPTIMER_TIMER_FORBIDDEN"
        : args.p_timer_id === ids.standalone
          ? "KEEPTIMER_ACCOUNT_DISABLED"
          : args.p_expected_revision === 9
            ? "KEEPTIMER_SYNC_REVISION_CONFLICT" : null;
      if (denial) return new Response(JSON.stringify({ code: "P0001", message: denial }),
        { status: 400, headers: { "Content-Type": "application/json" } });
      data = { created: true, duplicate: false,
        timer: { id: args.p_timer_id, sync_revision: 1 } };
    } else if (table === "keeptimer_delete_personal") {
      const args = JSON.parse(options.body);
      deleteCalls.push(args);
      data = { duplicate: false, timer: { id: args.p_timer_id, record_status: "deleted" } };
    } else if (table === "keeptimer_change_timer") {
      const args = JSON.parse(options.body);
      legacyCalls.push(args);
      data = { id: args.p_timer_id,
        record_status: args.p_delete ? "deleted" : "active", paused_count: 0 };
    } else throw new Error(`Unexpected Supabase request: ${method} ${url.pathname}`);
    return new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json" },
    });
  };

  let httpServer;
  try {
    const { generateAccessToken } = await import("../src/auth.js");
    ({ httpServer } = await import("../src/server.js"));
    if (!httpServer.listening) await once(httpServer, "listening");
    const origin = `http://127.0.0.1:${port}`;
    const token = generateAccessToken({ id: ids.worker }, ids.session);
    const request = async (method, path, body) => originalFetch(`${origin}${path}`, {
      method, headers: { Authorization: `Bearer ${token}`,
        "Content-Type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const personal = {
      dataMode: "workspace-personal", mutationId: ids.deleted,
      expectedRevision: 0, name: "Own", type: "up", targetMinutes: 1,
      isPay: false, status: "idle", accumulatedMs: 0, pausedCount: 0,
    };

    assert.equal((await request("POST", "/timers", {
      id: ids.personal, name: "Old", type: "up", targetMinutes: 0,
    })).status, 400);
    assert.equal(insertCalls.length, 0);
    assert.equal((await request("POST", "/timers", {
      id: ids.personal, name: "Local only", type: "up",
      targetMinutes: 1, dataMode: "standalone",
    })).status, 400);
    assert.equal(insertCalls.length, 0);
    const old = await request("POST", "/timers", {
      id: ids.personal, name: "Old", type: "up", targetMinutes: 1,
      user_id: ids.outsider, workspace_id: ids.otherCompany,
    });
    assert.equal(old.status, 200);
    assert.equal(insertCalls[0].user_id, ids.worker);
    assert.equal(insertCalls[0].workspace_id, ids.company);
    assert.equal((await request("PATCH", `/timers/${ids.personal}`,
      { is_pay: true })).status, 200);
    assert.equal((await request("DELETE", `/timers/${ids.personal}`)).status, 200);
    assert.equal(legacyCalls.length, 2);
    assert.equal((await request("POST", "/timers", {
      id: ids.shared, name: "Shared", type: "down",
      targetMinutes: 1, isShared: true,
    })).status, 403);

    assert.equal((await request("PUT", `/timers/personal/${ids.personal}`,
      { ...personal, dataMode: "standalone" })).status, 400);
    assert.equal((await request("PUT", `/timers/personal/${ids.personal}`,
      { ...personal, workspace_id: ids.otherCompany })).status, 400);
    assert.equal(syncCalls.length, 0);
    const created = await request("PUT", `/timers/personal/${ids.personal}`, personal);
    assert.equal(created.status, 201);
    assert.equal(syncCalls[0].p_actor_id, ids.worker);
    assert.equal(syncCalls[0].p_state.target_minutes, 1);
    assert.equal("user_id" in syncCalls[0].p_state, false);
    assert.equal((await request("PUT", `/timers/personal/${ids.outsider}`, personal)).status, 403);
    assert.equal((await request("PUT", `/timers/personal/${ids.standalone}`, personal)).status, 401);
    assert.equal((await request("PUT", `/timers/personal/${ids.personal}`,
      { ...personal, expectedRevision: 9 })).status, 409);

    const deleted = await request("DELETE", `/timers/personal/${ids.personal}`, {
      dataMode: "workspace-personal", mutationId: ids.standalone,
      expectedRevision: 1,
    });
    assert.equal(deleted.status, 200);
    assert.equal(deleteCalls[0].p_actor_id, ids.worker);
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(done => httpServer.close(done));
    }
  }
});
