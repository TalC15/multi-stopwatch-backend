import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { ids } from "./support/database.js";

test("pending personal Telegram job is cancelled and callback checks current archive state", async () => {
  process.env.JWT_SECRET = "local-only-notification-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-test-key";
  process.env.TELEGRAM_BOT_TOKEN = "test";
  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  process.env.PORT = String(port);

  let disabled = false;
  let archived = false;
  let messages = 0;
  let closeCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (request, options) => {
    const url = new URL(request.url ?? request);
    if (url.hostname === "api.telegram.org") {
      messages++;
      return new Response(JSON.stringify({ ok: true }));
    }
    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }
    const table = url.pathname.split("/").at(-1);
    let result;
    if (table === "keeptimer_close_company_worker") {
      assert.equal(JSON.parse(options.body).p_actor_id, ids.manager);
      disabled = true;
      archived = true;
      closeCalls++;
      result = { user_id: ids.worker, already_disabled: false,
        archived_timer_ids: [ids.personal] };
    } else if (table === "users") {
      if (url.searchParams.has("role")) result = { id: ids.superadmin };
      else if (url.searchParams.get("id")?.includes(ids.manager)) {
        result = { id: ids.manager, username: "manager", role: "manager",
          workspace_id: ids.company, disabled_at: null };
      } else {
        result = { id: ids.worker, username: "worker", role: "worker",
          workspace_id: ids.company, disabled_at: disabled ? new Date().toISOString() : null,
          telegram_chat_id: "chat-id" };
      }
    } else if (table === "sessions") {
      result = { id: url.searchParams.get("id")?.includes(ids.secondManager)
        ? ids.secondManager : ids.session, revoked_at: null };
    } else if (table === "timers") {
      result = { id: ids.personal, user_id: ids.worker,
        workspace_id: ids.company, is_shared: false, is_pay: false,
        record_status: "active", archived_at: archived ? new Date().toISOString() : null };
    } else throw new Error(`Unexpected mock request: ${url.pathname}`);
    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" },
    });
  };

  let httpServer;
  try {
    const { generateAccessToken } = await import("../src/auth.js");
    ({ httpServer } = await import("../src/server.js"));
    if (!httpServer.listening) await once(httpServer, "listening");
    const origin = `http://127.0.0.1:${port}`;
    const post = (path, token, body) => originalFetch(`${origin}${path}`, {
      method: "POST", headers: { "Content-Type": "application/json",
        Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
    });
    const workerToken = generateAccessToken({ id: ids.worker }, ids.session);
    const managerToken = generateAccessToken({ id: ids.manager }, ids.secondManager);

    // Simulate a job running after archival even without in-memory cancellation.
    const first = await post("/timer/start", workerToken,
      { timerId: ids.personal, timerName: "Personal", endsAt: Date.now() + 250 });
    assert.equal(first.status, 200);
    archived = true;
    disabled = true;
    await delay(350);
    assert.equal(messages, 0);

    // Also exercise the normal closing endpoint's immediate job cancellation.
    archived = false;
    disabled = false;
    const second = await post("/timer/start", workerToken,
      { timerId: ids.personal, timerName: "Personal", endsAt: Date.now() + 350 });
    assert.equal(second.status, 200);
    const closed = await originalFetch(`${origin}/users/${ids.worker}`, {
      method: "DELETE", headers: { Authorization: `Bearer ${managerToken}` },
    });
    assert.equal(closed.status, 200);
    assert.equal(closeCalls, 1);
    await delay(420);
    assert.equal(messages, 0);
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(resolve => httpServer.close(resolve));
    }
  }
});
