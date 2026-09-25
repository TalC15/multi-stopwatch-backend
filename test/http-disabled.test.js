import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { ids } from "./support/database.js";

test("login, refresh and protected API reject a deactivated worker", async () => {
  process.env.JWT_SECRET = "local-only-company-deactivation-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-test-key";

  const reservation = createServer().listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  process.env.PORT = String(port);

  const { hashPin, generateAccessToken, generateRefreshToken, hashToken } = await import("../src/auth.js");
  const worker = {
    id: ids.worker, username: "worker", role: "worker", workspace_id: ids.company,
    disabled_at: "2026-09-25T00:00:00Z", pin_hash: await hashPin("1234"),
  };
  const refreshToken = generateRefreshToken(worker, ids.session);
  let attemptedSessions = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (request, options) => {
    const url = new URL(request.url ?? request);
    if (url.hostname !== "127.0.0.1" || url.port !== "54321") {
      return originalFetch(request, options);
    }
    const table = url.pathname.split("/").at(-1);
    if (table === "sessions" && (options?.method || request.method) === "POST") attemptedSessions++;
    const result = table === "keeptimer_refresh_session" ? false : table === "sessions"
      ? { id: ids.session, user_id: ids.worker,
          revoked_at: null, refresh_token_hash: hashToken(refreshToken) }
      : url.searchParams.has("role") ? { id: ids.superadmin } : worker;
    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" },
    });
  };

  let httpServer;
  try {
    ({ httpServer } = await import("../src/server.js"));
    if (!httpServer.listening) await once(httpServer, "listening");
    const origin = `http://127.0.0.1:${port}`;
    const post = (path, body) => originalFetch(`${origin}${path}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const login = await post("/auth/login", { username: "worker", pin: "1234" });
    assert.equal(login.status, 401);
    assert.equal(attemptedSessions, 0);

    const refresh = await post("/auth/refresh", { refreshToken });
    assert.equal(refresh.status, 401);

    const access = await originalFetch(`${origin}/timers/personal`, {
      headers: { Authorization: `Bearer ${generateAccessToken(worker, ids.session)}` },
    });
    assert.equal(access.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) {
      httpServer.closeAllConnections();
      await new Promise(resolve => httpServer.close(resolve));
    }
  }
});
