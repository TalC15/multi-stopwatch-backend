import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { ids } from "./support/database.js";

test("personal pages include explicit terminal rows and continue beyond Supabase caps", async () => {
  process.env.JWT_SECRET = "local-phase4-pages";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-test-only";
  const reservation = createServer().listen(0, "127.0.0.1"); await once(reservation, "listening");
  const port = reservation.address().port; await new Promise(done => reservation.close(done)); process.env.PORT = String(port);
  const originalFetch = globalThis.fetch;
  const rows = Array.from({ length: 1003 }, (_, i) => ({
    id: `10000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}`,
    user_id: ids.worker, workspace_id: ids.company, is_shared: false,
    record_status: i % 3 === 0 ? "deleted" : "active", archived_at: i % 11 === 0 ? "2026-09-27T00:00:00Z" : null, sync_revision: i,
  }));
  let tableCalls = 0, fail = false, workspace = ids.company;
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);
    if (url.port !== "54321") return originalFetch(request, options);
    const table = url.pathname.split("/").at(-1);
    let data;
    if (table === "users") data = url.searchParams.has("role") ? { id: ids.superadmin } :
      { id: ids.worker, role: "worker", workspace_id: workspace, disabled_at: null };
    else if (table === "sessions") data = { id: ids.session, revoked_at: null };
    else if (table === "timers") {
      tableCalls++;
      assert.equal(url.searchParams.get("user_id"), `eq.${ids.worker}`);
      assert.equal(url.searchParams.get("workspace_id"), `eq.${ids.company}`);
      assert.equal(url.searchParams.get("is_shared"), "eq.false");
      if (fail) return new Response(JSON.stringify({ message: "unavailable" }), { status: 503 });
      if (url.searchParams.has("limit")) {
        assert.equal(url.searchParams.get("limit"), "200"); assert.equal(url.searchParams.get("order"), "id.asc");
        assert.equal(url.searchParams.has("record_status"), false);
        const after = url.searchParams.get("id")?.slice(3);
        data = rows.filter(row => !after || row.id > after).slice(0, 37);
      } else {
        assert.equal(url.searchParams.get("record_status"), "eq.active");
        assert.equal(url.searchParams.get("archived_at"), "is.null");
        data = rows.filter(row => row.record_status === "active" && !row.archived_at).slice(0, 37);
      }
    } else throw new Error(`Unexpected table ${table}`);
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
  };
  let server;
  try {
    const { generateAccessToken } = await import("../src/auth.js");
    ({ httpServer: server } = await import("../src/server.js"));
    if (!server.listening) await once(server, "listening");
    const token = generateAccessToken({ id: ids.worker }, ids.session);
    const get = path => originalFetch(`http://127.0.0.1:${port}${path}`, { headers: { Authorization: `Bearer ${token}` } });
    const old = await (await get("/timers/personal")).json(); assert.ok(Array.isArray(old.timers)); assert.equal(old.tombstones, undefined);
    let after = null, count = 0, terminalCount = 0;
    do {
      const response = await get(`/timers/personal?syncPage=1${after ? `&after=${after}` : ""}`);
      assert.equal(response.status, 200); const page = await response.json();
      count += page.timers.length + page.tombstones.length; terminalCount += page.tombstones.length;
      assert.ok(page.timers.every(row => row.record_status === "active" && !row.archived_at));
      assert.ok(page.tombstones.every(row => row.record_status === "deleted" || row.archived_at));
      after = page.nextCursor;
    } while (after !== null);
    assert.equal(count, 1003); assert.ok(terminalCount > 0);
    const before = tableCalls;
    assert.equal((await get("/timers/personal?syncPage=1&after=bad")).status, 400); assert.equal(tableCalls, before);
    assert.equal((await get("/timers/personal?syncPage=2")).status, 400);
    fail = true; assert.equal((await get("/timers/personal?syncPage=1")).status, 503);
    fail = false; workspace = null;
    assert.equal((await get("/timers/personal?syncPage=1")).status, 403);
    assert.equal((await get("/timers/personal")).status, 200);
  } finally {
    globalThis.fetch = originalFetch;
    if (server?.listening) { server.closeAllConnections(); await new Promise(done => server.close(done)); }
  }
});
