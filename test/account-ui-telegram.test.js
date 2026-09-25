import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { ids } from "./support/database.js";

test("active management lists exclude closed users; Telegram IDs stay scoped to the token", async () => {
  process.env.JWT_SECRET = "local-only-company-management-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-test-key";

  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  process.env.PORT = String(port);

  const closedId = "00000000-0000-4000-8000-000000000014";
  const users = new Map([
    [ids.manager, { id: ids.manager, username: "manager", role: "manager", workspace_id: ids.company, disabled_at: null }],
    [ids.worker, { id: ids.worker, username: "worker", role: "worker", workspace_id: ids.company, disabled_at: null, telegram_chat_id: "own-chat" }],
    [closedId, { id: closedId, username: "closed", role: "worker", workspace_id: ids.company, disabled_at: "2026-09-25T10:00:00Z" }],
    [ids.outsider, { id: ids.outsider, username: "other-company", role: "worker", workspace_id: ids.otherCompany, disabled_at: null, telegram_chat_id: "foreign-chat" }],
    [ids.superadmin, { id: ids.superadmin, username: "superadmin", role: "superadmin", workspace_id: null, disabled_at: null }],
  ]);
  const actualTelegramReads = [];
  const actualTelegramWrites = [];
  const originalFetch = globalThis.fetch;
  const eq = (url, key) => url.searchParams.get(key)?.replace(/^eq\./, "");

  globalThis.fetch = async (request, options) => {
    const url = new URL(request.url ?? request);
    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }
    const table = url.pathname.split("/").at(-1);
    const method = options?.method || request.method || "GET";
    const rowId = eq(url, "id");
    let data;
    if (table === "users" && method === "PATCH") {
      const target = users.get(rowId);
      const update = JSON.parse(options.body);
      if (update.role === "manager" && target.role === "worker" && target.workspace_id) {
        return new Response(JSON.stringify({ message: "KEEPTIMER_COMPANY_ROLE_IMMUTABLE", code: "P0001" }),
          { status: 400, headers: { "Content-Type": "application/json" } });
      }
      Object.assign(target, update);
      if ("telegram_chat_id" in update) actualTelegramWrites.push(rowId);
      return new Response(null, { status: 204 });
    }
    if (table === "users") {
      if (rowId) {
        if (url.searchParams.get("select") === "telegram_chat_id") actualTelegramReads.push(rowId);
        data = users.get(rowId);
      } else if (eq(url, "role") === "superadmin") {
        data = users.get(ids.superadmin);
      } else {
        data = [...users.values()];
        if (eq(url, "workspace_id")) data = data.filter(u => u.workspace_id === eq(url, "workspace_id"));
        if (url.searchParams.get("disabled_at") === "is.null") data = data.filter(u => !u.disabled_at);
      }
    } else if (table === "sessions") {
      data = { id: eq(url, "id"), revoked_at: null };
    } else if (table === "workspaces") {
      data = { id: eq(url, "id"), name: "Company A", invite_code: "LOCAL1" };
    } else {
      throw new Error(`Unexpected mock request: ${method} ${url.pathname}`);
    }
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
  };

  let httpServer;
  try {
    const { generateAccessToken } = await import("../src/auth.js");
    ({ httpServer } = await import("../src/server.js"));
    if (!httpServer.listening) await once(httpServer, "listening");
    const base = `http://127.0.0.1:${port}`;
    const request = async (method, path, userId, body) => {
      const response = await originalFetch(`${base}${path}`, {
        method,
        headers: { Authorization: `Bearer ${generateAccessToken(users.get(userId), ids.session)}`,
          "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      return { status: response.status, body: await response.json() };
    };

    const workers = await request("GET", "/users", ids.manager);
    assert.equal(workers.status, 200);
    assert.deepEqual(workers.body.users.map(u => u.id).sort(), [ids.manager, ids.worker].sort());

    const allActive = await request("GET", "/admin/users", ids.superadmin);
    assert.equal(allActive.status, 200);
    assert.equal(allActive.body.users.some(u => u.id === closedId), false);
    assert.equal(allActive.body.users.some(u => u.id === ids.outsider), true);

    const members = await request("GET", `/admin/workspaces/${ids.company}`, ids.superadmin);
    assert.equal(members.status, 200);
    assert.equal(members.body.members.some(u => u.id === closedId), false);

    const promoted = await request("PATCH", `/admin/users/${ids.worker}`, ids.superadmin,
      { username: "worker", role: "manager", workspace_id: ids.company });
    assert.equal(promoted.status, 409);
    assert.equal(users.get(ids.worker).role, "worker");
    assert.equal((await request("POST", "/workspace/leave", ids.manager, {})).status, 403);
    assert.equal((await request("POST", "/workspace/join", ids.worker, { inviteCode: "LOCAL1" })).status, 403);

    const foreignRead = await request("POST", "/telegram/control", ids.worker, { user_id: ids.outsider });
    assert.equal(foreignRead.status, 403);
    const foreignWrite = await request("PATCH", "/telegram/cancel", ids.worker, { user_id: ids.outsider });
    assert.equal(foreignWrite.status, 403);
    assert.deepEqual(actualTelegramReads, []);
    assert.deepEqual(actualTelegramWrites, []);

    const ownRead = await request("POST", "/telegram/control", ids.worker, { user_id: ids.worker });
    assert.deepEqual(ownRead.body, { success: true, connected: true });
    const ownWrite = await request("PATCH", "/telegram/cancel", ids.worker, { user_id: ids.worker });
    assert.equal(ownWrite.status, 200);
    assert.ok(ownWrite.body.success);
    const withoutId = await request("POST", "/telegram/control", ids.worker, {});
    assert.deepEqual(withoutId.body, { success: true, connected: false });
    assert.deepEqual(actualTelegramReads, [ids.worker, ids.worker]);
    assert.deepEqual(actualTelegramWrites, [ids.worker]);
    assert.equal(users.get(ids.outsider).telegram_chat_id, "foreign-chat");
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(resolve => httpServer.close(resolve));
    }
  }
});
