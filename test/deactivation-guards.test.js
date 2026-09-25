
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";

const uuid = n =>
  `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

const companyA = uuid(1), companyB = uuid(2);
const manager = uuid(3), worker = uuid(4);
const foreignManager = uuid(5);
const superadmin = uuid(6), sharedTimer = uuid(10);

const sessions = new Map([
  [manager, uuid(31)],
  [worker, uuid(32)],
  [foreignManager, uuid(33)],
]);

const people = new Map([
  [manager, {
    id: manager, username: "manager", role: "manager",
    workspace_id: companyA, disabled_at: null
  }],
  [worker, {
    id: worker, username: "worker", role: "worker",
    workspace_id: companyA, disabled_at: null
  }],
  [foreignManager, {
    id: foreignManager, username: "foreign", role: "manager",
    workspace_id: companyB, disabled_at: null
  }],
  [superadmin, {
    id: superadmin, username: "admin", role: "superadmin",
    workspace_id: null, disabled_at: null
  }],
]);

test("Phase 2B: deactivation guards", async t => {
  process.env.JWT_SECRET = "phase2b-local-test-only-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-test-key";

  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(done => reservation.close(done));
  process.env.PORT = String(port);

  const originalFetch = globalThis.fetch;
  const eq = (url, key) =>
    url.searchParams.get(key)?.replace(/^eq\./, "");

  let rpcCalls = 0;

  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);

    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }

    const table = url.pathname.split("/").at(-1);
    let data;

    if (table === "users") {
      data = eq(url, "id")
        ? people.get(eq(url, "id"))
        : eq(url, "role") === "superadmin"
          ? people.get(superadmin)
          : [];
    } else if (table === "sessions") {
      data = {
        id: eq(url, "id"),
        revoked_at: null
      };
    } else if (table === "timers") {
      data = {
        id: sharedTimer,
        user_id: manager,
        workspace_id: companyA,
        is_shared: true,
        record_status: "active",
        archived_at: null
      };
    } else if (table === "keeptimer_close_company_worker") {
      rpcCalls++;

      // RPC yanıtı belirsiz: DB işlemi hâlâ sürüyor olabilir.
      return new Response(JSON.stringify({
        code: "PGRST504",
        message: "gateway timeout"
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    } else {
      throw new Error(
        `Unexpected mocked request: ${url.pathname}`
      );
    }

    return new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json" }
    });
  };

  let httpServer;

  try {
    const { generateAccessToken } =
      await import("../src/auth.js");

    ({ httpServer } = await import("../src/server.js"));

    if (!httpServer.listening) {
      await once(httpServer, "listening");
    }

    const base = `http://127.0.0.1:${port}`;

    const request = async (method, path, actor, body) =>
      originalFetch(`${base}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${
            generateAccessToken(
              people.get(actor),
              sessions.get(actor)
            )
          }`,
          "Content-Type": "application/json"
        },
        ...(body ? { body: JSON.stringify(body) } : {})
      });

    await t.test(
      "foreign manager cannot block another company's worker",
      async () => {
        const response = await request(
          "DELETE",
          `/users/${worker}`,
          foreignManager
        );

        assert.equal(response.status, 403);
        assert.equal(rpcCalls, 0);

        const cancel = await request(
          "POST",
          "/timer/cancel",
          worker,
          { timerId: sharedTimer }
        );

        assert.equal(cancel.status, 200);
      }
    );

    await t.test(
      "ambiguous closure keeps notifications blocked",
      async () => {
        const response = await request(
          "DELETE",
          `/users/${worker}`,
          manager
        );

        assert.equal(response.status, 503);
        assert.equal(rpcCalls, 1);
        assert.equal(people.get(worker).disabled_at, null);

        const cancel = await request(
          "POST",
          "/timer/cancel",
          worker,
          { timerId: sharedTimer }
        );

        assert.equal(cancel.status, 409);
      }
    );
  } finally {
    globalThis.fetch = originalFetch;

    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(done => httpServer.close(done));
    }
  }
});
