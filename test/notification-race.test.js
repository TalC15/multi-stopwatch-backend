import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { ids } from "./support/database.js";

const extraIds = [13, 14, 15, 16, 17].map(n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`);
const timerIds = [18, 19, 20, 21, 22].map(n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`);
const sessionIds = [23, 24, 25, 26, 27].map(n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test("a closing worker cannot reschedule or cancel a shared Telegram job", async t => {
  process.env.JWT_SECRET = "local-only-shared-job-race-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-test-key";
  process.env.TELEGRAM_BOT_TOKEN = "local-test";
  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(done => reservation.close(done));
  process.env.PORT = String(port);

  const workerState = new Map(extraIds.map(id => [id, { disabled: false }]));
  const workerBySession = new Map(sessionIds.map((id, index) => [id, extraIds[index]]));
  const timerRows = new Map(timerIds.map((id, index) => [id, {
    id, user_id: extraIds[index], workspace_id: ids.company,
    is_shared: true, record_status: "active", archived_at: null, is_pay: false,
  }]));
  const notifications = [];
  let nextNotification = deferred();
  let heldRequest = null;
  let heldWorkerAuth = null;
  let heldClosure = null;
  const originalFetch = globalThis.fetch;
  const eq = (url, key) => url.searchParams.get(key)?.replace(/^eq\./, "");

  globalThis.fetch = async (request, options) => {
    const url = new URL(request.url ?? request);
    if (url.hostname === "api.telegram.org") {
      const message = url.searchParams.get("text");
      notifications.push(message);
      nextNotification.resolve(message);
      return new Response(JSON.stringify({ ok: true }));
    }
    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }

    const table = url.pathname.split("/").at(-1);
    const rowId = eq(url, "id");
    let data;
    if (table === "keeptimer_close_company_worker") {
      const args = JSON.parse(options.body);
      assert.equal(args.p_actor_id, ids.manager);
      assert.ok(workerState.has(args.p_worker_id));
      if (heldClosure?.id === args.p_worker_id) {
        const hold = heldClosure;
        heldClosure = null;
        hold.reached.resolve();
        await hold.release.promise;
      }
      workerState.get(args.p_worker_id).disabled = true;
      data = { already_disabled: false, archived_timer_ids: [] };
    } else if (table === "users") {
      if (rowId === ids.manager) {
        data = { id: ids.manager, role: "manager", workspace_id: ids.company,
          disabled_at: null, telegram_chat_id: "manager-chat" };
      } else if (workerState.has(rowId)) {
        const state = workerState.get(rowId);
        data = { id: rowId, role: "worker", workspace_id: ids.company,
          disabled_at: state.disabled ? "2026-09-25T00:00:00Z" : null };
        // Return an active snapshot even though the closure commits while the
        // last auth check is awaiting its HTTP response.
        if (heldWorkerAuth?.id === rowId && ++heldWorkerAuth.reads === 2) {
          const hold = heldWorkerAuth;
          heldWorkerAuth = null;
          hold.reached.resolve();
          await hold.release.promise;
        }
      } else if (eq(url, "role") === "superadmin") {
        data = { id: ids.superadmin };
      } else {
        data = [{ id: ids.manager, telegram_chat_id: "manager-chat" }];
      }
    } else if (table === "sessions") {
      const actor = workerBySession.get(rowId);
      data = { id: rowId, revoked_at: workerState.get(actor)?.disabled
        ? "2026-09-25T00:00:00Z" : null };
    } else if (table === "timers") {
      data = timerRows.get(rowId);
      if (heldRequest?.id === rowId && url.searchParams.get("select")?.startsWith("id,")) {
        const hold = heldRequest;
        heldRequest = null;
        hold.reached.resolve();
        await hold.release.promise;
      }
    } else {
      throw new Error(`Unexpected fake Supabase request: ${url.pathname}`);
    }
    return new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json" },
    });
  };

  let httpServer;
  try {
    const { generateAccessToken } = await import("../src/auth.js");
    const { cancelTimer } = await import("../src/timers.js");
    ({ httpServer } = await import("../src/server.js"));
    if (!httpServer.listening) await once(httpServer, "listening");
    const origin = `http://127.0.0.1:${port}`;
    const managerToken = generateAccessToken({ id: ids.manager }, ids.secondManager);
    const send = (method, path, token, body) => originalFetch(`${origin}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });

    for (const [index, scenario] of [
      { endpoint: "start", hold: "timer" },
      { endpoint: "cancel", hold: "timer" },
      { endpoint: "start", hold: "fresh-auth" },
      { endpoint: "cancel", hold: "fresh-auth" },
      { endpoint: "cancel", hold: "pending-close" },
    ].entries()) {
      await t.test(`${scenario.endpoint}: closure during ${scenario.hold} preserves the shared job`, async () => {
        const actorId = extraIds[index];
        const timerId = timerIds[index];
        const workerToken = generateAccessToken({ id: actorId }, sessionIds[index]);
        const originalName = `original-${index}`;
        nextNotification = deferred();
        const scheduled = await send("POST", "/timer/start", workerToken,
          { timerId, timerName: originalName, endsAt: Date.now() + 700 });
        assert.equal(scheduled.status, 200);

        const hold = { id: scenario.hold === "fresh-auth" ? actorId : timerId,
          reached: deferred(), release: deferred(), reads: 0 };
        if (scenario.hold !== "fresh-auth") heldRequest = hold;
        else heldWorkerAuth = hold;
        const stale = send("POST", `/timer/${scenario.endpoint}`, workerToken,
          { timerId, timerName: "stale", endsAt: Date.now() + 10_000 });
        await hold.reached.promise;
        if (scenario.hold === "pending-close") {
          const rpcHold = { id: actorId, reached: deferred(), release: deferred() };
          heldClosure = rpcHold;
          const closing = send("DELETE", `/users/${actorId}`, managerToken);
          await rpcHold.reached.promise;
          // The database still reports an active account here: only the
          // process-local guard can protect the existing shared job.
          hold.release.resolve();
          assert.equal((await stale).status, 409);
          rpcHold.release.resolve();
          assert.equal((await closing).status, 200);
        } else {
          const closed = await send("DELETE", `/users/${actorId}`, managerToken);
          assert.equal(closed.status, 200);
          hold.release.resolve();
          const lateResult = await stale;
          assert.equal(lateResult.status, scenario.hold === "fresh-auth" ? 409 : 401);
        }

        const expected = `${originalName} bitti! ODENMEDI`;
        let watchdog;
        const received = await Promise.race([
          nextNotification.promise,
          new Promise((_, reject) => {
            watchdog = setTimeout(() => reject(new Error("Shared job lost")), 1600);
          }),
        ]).finally(() => clearTimeout(watchdog));
        assert.equal(received, expected);
        assert.equal(notifications.filter(message => message === expected).length, 1);
        cancelTimer(timerId);
      });
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(done => httpServer.close(done));
    }
  }
});
