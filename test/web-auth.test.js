import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import express from "express";
import jwt from "jsonwebtoken";
import {
  createWebAuthGuard, parseAuthOrigins, readRefreshCookie, REFRESH_COOKIE_NAME,
} from "../src/webAuth.js";

const origin = "https://keeptimer.example";
const csrfHeaders = { Origin: origin, "Content-Type": "application/json", "X-KeepTimer-CSRF": "1" };
const cookie = token => `${REFRESH_COOKIE_NAME}=${token}`;
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type": "application/json" },
});
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
function assertNoStore(response) {
  for (const name of ["Cache-Control", "CDN-Cache-Control", "Vercel-CDN-Cache-Control"]) {
    assert.equal(response.headers.get(name), "no-store");
  }
}
function cookieAttributes(header) {
  return header.split(";").slice(1).map(part => part.trim()).filter(part => !part.startsWith("Expires=")).sort();
}

test("origin configuration is exact and fails closed", () => {
  assert.deepEqual([...parseAuthOrigins(`${origin}, http://localhost:5173`)], [origin, "http://localhost:5173"]);
  assert.equal(parseAuthOrigins().size, 0);
  for (const value of ["*", "null", "http://example.com", `${origin}/`, `${origin}/path`,
    "https://user:secret@keeptimer.example", "https://*.vercel.app", `${origin}?x=1`]) {
    assert.throws(() => parseAuthOrigins(value));
  }
});

test("cookie parser rejects duplicate, malformed and oversized values", () => {
  for (const value of ["", cookie(""), cookie("%zz"), `${cookie("one")}; ${cookie("two")}`, cookie("a".repeat(4097))]) {
    assert.equal(readRefreshCookie({ headers: { cookie: value } }), null);
  }
  assert.equal(readRefreshCookie({ headers: { cookie: `unrelated=ok; ${cookie("a.b.c")}` } }), "a.b.c");
});

test("missing origin configuration disables only web auth", async t => {
  const app = express();
  app.use("/auth/login", createWebAuthGuard(parseAuthOrigins()));
  app.get("/health", (req, res) => res.json({ ok: true }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise(done => server.close(done)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const response = await fetch(`${base}/auth/login`, { method: "POST", headers: csrfHeaders, body: "{}" });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).code, "AUTH_NOT_CONFIGURED");
  assertNoStore(response);
  assert.equal((await fetch(`${base}/health`)).status, 200);
});

test("web/native auth HTTP, proxy, session and Socket.IO contract", { timeout: 120000 }, async t => {
  process.env.JWT_SECRET = "only-local-web-auth-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "only-local-test-key";
  process.env.AUTH_ALLOWED_ORIGINS = `${origin},http://localhost:5173`;
  process.env.PORT = "0";
  const auth = await import("../src/auth.js");
  const workspaceId = randomUUID();
  const users = new Map();
  for (const role of ["worker", "manager", "superadmin"]) {
    users.set(role, { id: randomUUID(), username: role, role, workspace_id: role === "superadmin" ? null : workspaceId,
      disabled_at: null, pin_hash: await auth.hashPin("1234") });
  }
  const sessions = new Map();
  const writes = [];
  let failure = null, heldUpdate = null, group = 0;
  const originalFetch = globalThis.fetch;
  const eq = (url, key) => url.searchParams.get(key)?.replace(/^eq\./, "");
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);
    if (url.origin !== "http://127.0.0.1:54321") {
      assert.ok(["127.0.0.1", "localhost"].includes(url.hostname), "tests must not contact live services");
      return originalFetch(request, options);
    }
    const table = url.pathname.split("/").at(-1);
    const method = options.method || request.method || "GET";
    const body = options.body ? JSON.parse(options.body) : null;
    if (failure?.table === table && (!failure.method || failure.method === method)) {
      return json({ code: failure.code || "TEST_FAILURE", message: failure.message || "backend unavailable" }, failure.status || 503);
    }
    if (table === "users") {
      const user = [...users.values()].find(user =>
        (!eq(url, "id") || user.id === eq(url, "id")) &&
        (!eq(url, "role") || user.role === eq(url, "role")) &&
        (!eq(url, "username") || user.username === eq(url, "username")));
      return user ? json(user) : json({ code: "PGRST116", message: "not found" }, 406);
    }
    if (table === "sessions") {
      if (method === "POST") {
        sessions.set(body.id, { ...body, revoked_at: null });
        writes.push({ method, row: body });
        return json(null, 201);
      }
      const matches = [...sessions.values()].filter(session =>
        (!eq(url, "id") || session.id === eq(url, "id")) &&
        (!eq(url, "user_id") || session.user_id === eq(url, "user_id")) &&
        (url.searchParams.get("revoked_at") !== "is.null" || !session.revoked_at));
      if (method === "PATCH") {
        const hold = heldUpdate;
        if (hold) { heldUpdate = null; hold.reached.resolve(); await hold.release.promise; }
        writes.push({ method, ids: matches.map(row => row.id), filters: Object.fromEntries(url.searchParams), body });
        matches.forEach(row => Object.assign(row, body));
        return json(null);
      }
      return matches[0] ? json(matches[0]) : json({ code: "PGRST116", message: "not found" }, 406);
    }
    if (table === "keeptimer_refresh_session") {
      const row = sessions.get(body.p_session_id);
      const user = [...users.values()].find(user => user.id === body.p_user_id);
      return json(Boolean(row && user && !user.disabled_at && !row.revoked_at &&
        row.user_id === user.id && row.refresh_token_hash === body.p_token_hash));
    }
    if (table === "keeptimer_close_company_worker") {
      const actor = [...users.values()].find(user => user.id === body.p_actor_id);
      const worker = [...users.values()].find(user => user.id === body.p_worker_id);
      assert.ok(["manager", "superadmin"].includes(actor.role));
      assert.equal(worker.role, "worker");
      assert.ok(actor.role === "superadmin" || actor.workspace_id === worker.workspace_id);
      worker.disabled_at = new Date().toISOString();
      for (const row of sessions.values()) if (row.user_id === worker.id) row.revoked_at = worker.disabled_at;
      return json({ already_disabled: false, archived_timer_ids: [] });
    }
    if (table === "timers") return json([]);
    throw new Error(`Unexpected mock route: ${method} ${table}`);
  };
  const { httpServer } = await import("../src/server.js");
  if (!httpServer.listening) await once(httpServer, "listening");
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const engines = new Set();
  t.after(async () => {
    for (const sid of engines) {
      await originalFetch(`${base}/socket.io/?EIO=4&transport=polling&sid=${sid}`, {
        method: "POST", body: "1", signal: AbortSignal.timeout(2000),
      }).catch(() => {});
    }
    globalThis.fetch = originalFetch;
    httpServer.closeAllConnections();
    await new Promise(done => httpServer.close(done));
  });
  t.beforeEach(() => {
    group++;
    failure = null;
    writes.length = 0;
    for (const user of users.values()) user.disabled_at = null;
  });
  const request = (path, body = {}, extra = {}) => originalFetch(`${base}${path}`, {
    method: "POST", headers: { ...csrfHeaders, "X-Forwarded-For": `198.51.100.${group}`, ...extra }, body: JSON.stringify(body),
  });
  const login = (username = "worker") => request("/auth/login", { username, pin: "1234" });
  const nativeRequest = async (action, body = {}, headers = {}) => {
    const response = await originalFetch(`${base}/auth/native/${action}`, {
      method: "POST", headers: {
        "Content-Type": "application/json", "X-Forwarded-For": `198.51.100.${group}`, ...headers,
      }, body: JSON.stringify(body),
    });
    assertNoStore(response);
    assert.equal(response.headers.get("set-cookie"), null);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.equal(response.headers.get("access-control-allow-credentials"), null);
    return response;
  };
  const nativeSession = (action, session, body = { sessionId: session.id }, headers = {}) =>
    nativeRequest(action, body, { Authorization: `Bearer ${session.token}`, ...headers });
  const makeSession = (role = "worker", id = randomUUID()) => {
    const user = users.get(role);
    const token = auth.generateRefreshToken(user, id);
    sessions.set(id, { id, user_id: user.id, refresh_token_hash: auth.hashToken(token), revoked_at: null });
    return { id, token, access: auth.generateAccessToken(user, id) };
  };
  const sessionRequest = (path, session, body = { sessionId: session.id }, extra = {}) =>
    request(path, body, { Cookie: cookie(session.token), ...extra });
  const bearerRequest = (path, session, method = "POST", body = {}) => originalFetch(`${base}${path}`, {
    method, headers: { Authorization: `Bearer ${session.access}`, "Content-Type": "application/json" },
    ...(method !== "GET" ? { body: JSON.stringify(body) } : {}),
  });
  const connectSocket = async token => {
    const opened = await originalFetch(`${base}/socket.io/?EIO=4&transport=polling`);
    const { sid } = JSON.parse((await opened.text()).slice(1));
    engines.add(sid);
    const endpoint = `${base}/socket.io/?EIO=4&transport=polling&sid=${sid}`;
    await originalFetch(endpoint, { method: "POST", body: `40${JSON.stringify(token ? { token } : {})}` });
    const packet = await (await originalFetch(endpoint, { signal: AbortSignal.timeout(2000) })).text();
    return { sid, endpoint, packet };
  };
  const assertDisconnected = async socket => {
    const response = await originalFetch(socket.endpoint, { signal: AbortSignal.timeout(2000) });
    const packet = await response.text();
    assert.ok(response.status === 400 || packet.split("\x1e").some(part => part === "1" || part.startsWith("41")), packet);
  };

  await t.test("login returns access and public session identity, never refresh JSON", async () => {
    const response = await login();
    assert.equal(response.status, 200);
    assertNoStore(response);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), ["accessToken", "sessionId", "user"]);
    const header = response.headers.get("set-cookie");
    assert.match(header, /^__Secure-keeptimer-refresh=/);
    assert.deepEqual(cookieAttributes(header), ["HttpOnly", "Path=/api/auth", "SameSite=Lax", "Secure"]);
    const refresh = auth.verifyToken(header.split(";")[0].split("=")[1]);
    const access = auth.verifyToken(body.accessToken);
    assert.equal(refresh.type, "refresh");
    assert.equal(access.type, "access");
    assert.equal(access.exp - access.iat, 900);
    assert.equal(refresh.exp - refresh.iat, 30 * 24 * 60 * 60);
    assert.equal(new Date(header.match(/Expires=([^;]+)/)[1]).getTime(), refresh.exp * 1000);
    assert.equal(body.sessionId, refresh.sessionId);
    assert.equal(body.sessionId, access.sessionId);
    assert.deepEqual(body.user, { id: users.get("worker").id, username: "worker", role: "worker", workspace_id: workspaceId });
    assert.equal(sessions.get(body.sessionId).refresh_token_hash, auth.hashToken(header.split(";")[0].split("=")[1]));
    assert.equal((await bearerRequest("/telegram/control", { access: body.accessToken })).status, 200);
    assert.equal(response.headers.get("access-control-allow-origin"), origin);
  });
  await t.test("valid cookie refresh preserves JWT session without rotation or cookie rewrite", async () => {
    const session = makeSession();
    const response = await sessionRequest("/auth/refresh", session);
    assert.equal(response.status, 200);
    assertNoStore(response);
    assert.equal(response.headers.get("set-cookie"), null);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), ["accessToken", "sessionId"]);
    assert.equal(auth.verifyToken(body.accessToken).sessionId, session.id);
    assert.equal(body.sessionId, session.id);
    assert.equal(sessions.get(session.id).refresh_token_hash, auth.hashToken(session.token));
  });
  await t.test("missing, malformed, expired, wrong-signature and wrong-type cookies fail", async () => {
    const session = makeSession();
    const expired = jwt.sign({ id: users.get("worker").id, sessionId: session.id, type: "refresh" }, process.env.JWT_SECRET, { expiresIn: -1 });
    const forged = jwt.sign({ id: users.get("worker").id, sessionId: session.id, type: "refresh" }, "wrong-secret");
    for (const value of ["", cookie("broken"), cookie("%zz"), cookie(expired), cookie(forged), cookie(session.access),
      `${cookie(session.token)}; ${cookie(session.token)}`]) {
      for (const path of ["/auth/refresh", "/auth/logout"]) {
        const response = await request(path, { sessionId: session.id }, { Cookie: value });
        assert.equal(response.status, 401);
        assert.equal(response.headers.get("set-cookie"), null);
        assertNoStore(response);
      }
    }
    assert.equal(sessions.get(session.id).revoked_at, null);
  });
  await t.test("JSON refresh tokens and missing session guards are not fallback credentials", async () => {
    const session = makeSession();
    for (const body of [{ refreshToken: session.token }, {}, { sessionId: session.id, refreshToken: session.token },
      { sessionId: 4 }, { sessionId: "bad" }, [], null]) {
      for (const path of ["/auth/refresh", "/auth/logout"]) {
        const response = await sessionRequest(path, session, body);
        assert.equal(response.status, 400);
        assert.equal(response.headers.get("set-cookie"), null);
      }
    }
  });
  await t.test("unknown session and hash mismatch cannot refresh or logout", async () => {
    for (const kind of ["unknown", "hash"]) {
      const session = makeSession();
      if (kind === "unknown") sessions.delete(session.id);
      else sessions.get(session.id).refresh_token_hash = "not-the-token-hash";
      for (const path of ["/auth/refresh", "/auth/logout"]) {
        const response = await sessionRequest(path, session);
        assert.equal(response.status, 401);
        assert.equal(response.headers.get("set-cookie"), null);
      }
    }
    assert.equal(writes.length, 0);
  });
  await t.test("logout revokes only the cookie session and matches cookie deletion scope", async () => {
    const loginResponse = await login();
    const loginBody = await loginResponse.json();
    const creationCookie = loginResponse.headers.get("set-cookie");
    const session = { id: loginBody.sessionId, token: creationCookie.split(";")[0].split("=")[1], access: loginBody.accessToken };
    const other = makeSession();
    const socket = await connectSocket(session.access);
    assert.match(socket.packet, /^40/);
    const response = await sessionRequest("/auth/logout", session);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, sessionId: session.id });
    assertNoStore(response);
    const cleared = response.headers.get("set-cookie");
    assert.deepEqual(cookieAttributes(cleared), cookieAttributes(creationCookie));
    assert.match(cleared, /^__Secure-keeptimer-refresh=;/);
    assert.ok(new Date(cleared.match(/Expires=([^;]+)/)[1]).getTime() < Date.now());
    assert.ok(sessions.get(session.id).revoked_at);
    assert.equal(sessions.get(other.id).revoked_at, null);
    assert.equal(writes.at(-1).filters.id, `eq.${session.id}`);
    assert.equal(writes.at(-1).filters.user_id, `eq.${users.get("worker").id}`);
    await assertDisconnected(socket);
    assert.equal((await sessionRequest("/auth/refresh", session)).status, 401);
    assert.equal((await bearerRequest("/telegram/control", session)).status, 401);
    assert.equal((await sessionRequest("/auth/logout", session)).status, 200, "lost-response retry is idempotent while cookie remains");
  });
  await t.test("stale A request carrying B cookie cannot refresh, revoke or clear B", async () => {
    const a = makeSession(), b = makeSession("manager");
    for (const path of ["/auth/refresh", "/auth/logout"]) {
      const response = await sessionRequest(path, b, { sessionId: a.id });
      assert.equal(response.status, 409);
      assert.equal((await response.json()).code, "AUTH_SESSION_CHANGED");
      assert.equal(response.headers.get("set-cookie"), null);
    }
    assert.equal(writes.length, 0);
    assert.equal(sessions.get(a.id).revoked_at, null);
    assert.equal(sessions.get(b.id).revoked_at, null);
  });
  await t.test("delayed A logout revokes A only; its Set-Cookie still requires frontend serialization", async () => {
    const a = makeSession();
    const hold = { reached: deferred(), release: deferred() };
    heldUpdate = hold;
    const pending = sessionRequest("/auth/logout", a);
    await hold.reached.promise;
    let b;
    try {
      const response = await login("manager");
      assert.equal(response.status, 200);
      b = await response.json();
    } finally { hold.release.resolve(); }
    const response = await pending;
    assert.equal(response.status, 200);
    assert.ok(sessions.get(a.id).revoked_at);
    assert.equal(sessions.get(b.sessionId).revoked_at, null);
    assert.ok(response.headers.get("set-cookie"), "backend cannot stop a delayed browser cookie deletion");
  });
  await t.test("disabled account rejects login, refresh, Bearer and socket access", async () => {
    const session = makeSession();
    users.get("worker").disabled_at = new Date().toISOString();
    assert.equal((await login()).status, 401);
    assert.equal(writes.length, 0);
    assert.equal((await sessionRequest("/auth/refresh", session)).status, 401);
    assert.equal((await bearerRequest("/telegram/control", session)).status, 401);
    const socket = await connectSocket(session.access);
    assert.match(socket.packet, /^44/);
    assert.equal(JSON.parse(socket.packet.slice(2)).data.status, 401);
  });
  await t.test("account closure during session creation/refresh is still rejected", async () => {
    const session = makeSession();
    failure = { table: "sessions", method: "POST", code: "P0001", message: "KEEPTIMER_ACCOUNT_DISABLED", status: 400 };
    const loginResponse = await login();
    assert.equal(loginResponse.status, 401);
    assert.equal(loginResponse.headers.get("set-cookie"), null);
    failure = { table: "keeptimer_refresh_session", method: "POST", code: "P0001", message: "KEEPTIMER_ACCOUNT_DISABLED", status: 400 };
    const refreshResponse = await sessionRequest("/auth/refresh", session);
    assert.equal(refreshResponse.status, 401);
    assert.equal(refreshResponse.headers.get("set-cookie"), null);
  });
  await t.test("superadmin force-logout closes target sockets and all target sessions only", async () => {
    const worker = makeSession(), second = makeSession(), manager = makeSession("manager"), admin = makeSession("superadmin");
    const socket = await connectSocket(worker.access);
    assert.match(socket.packet, /^40/);
    const path = `/users/${users.get("worker").id}/force-logout`;
    assert.equal((await bearerRequest(path, manager)).status, 403, "existing role restriction must not be widened");
    assert.equal((await bearerRequest(path, admin)).status, 200);
    assert.ok(sessions.get(worker.id).revoked_at);
    assert.ok(sessions.get(second.id).revoked_at);
    assert.equal(sessions.get(manager.id).revoked_at, null);
    assert.equal((await sessionRequest("/auth/refresh", worker)).status, 401);
    await assertDisconnected(socket);
  });
  for (const actor of ["manager", "superadmin"]) await t.test(`${actor} account closure retains session and socket revocation`, async () => {
    const worker = makeSession(), admin = makeSession(actor);
    const socket = await connectSocket(worker.access);
    assert.match(socket.packet, /^40/);
    const response = await bearerRequest(`/users/${users.get("worker").id}`, admin, "DELETE");
    assert.equal(response.status, 200);
    assert.ok(users.get("worker").disabled_at);
    assert.ok(sessions.get(worker.id).revoked_at);
    assert.equal((await sessionRequest("/auth/refresh", worker)).status, 401);
    await assertDisconnected(socket);
  });
  await t.test("Socket.IO still requires a valid Bearer-style access JWT, not the cookie", async () => {
    const session = makeSession();
    for (const token of [null, session.token, "broken"]) {
      const socket = await connectSocket(token);
      assert.match(socket.packet, /^44/);
      assert.equal(JSON.parse(socket.packet.slice(2)).data.status, 401);
    }
    sessions.get(session.id).revoked_at = new Date().toISOString();
    assert.match((await connectSocket(session.access)).packet, /^44/);
  });
  await t.test("database failures are transient and never delete a cookie or report logout success", async () => {
    const session = makeSession();
    failure = { table: "users" };
    assert.equal((await login()).status, 503);
    failure = { table: "sessions", method: "POST" };
    const failedLogin = await login();
    assert.equal(failedLogin.status, 503);
    assert.equal(failedLogin.headers.get("set-cookie"), null);
    for (const [path, table, method] of [["/auth/refresh", "sessions", "GET"], ["/auth/refresh", "keeptimer_refresh_session", "POST"],
      ["/auth/logout", "sessions", "GET"], ["/auth/logout", "sessions", "PATCH"]]) {
      failure = { table, method };
      const response = await sessionRequest(path, session);
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("set-cookie"), null);
      assertNoStore(response);
    }
    assert.equal(sessions.get(session.id).revoked_at, null);
  });
  await t.test("unexpected auth failure returns a generic no-store response without credentials", async () => {
    const worker = users.get("worker");
    const originalHash = worker.pin_hash;
    worker.pin_hash = 42; // bcrypt rejects a corrupt upstream value with an exception.
    try {
      const response = await login();
      assert.equal(response.status, 503);
      assertNoStore(response);
      assert.deepEqual(await response.json(), {
        error: "Sunucu geçici olarak erişilemiyor", code: "AUTH_UNAVAILABLE",
      });
      assert.equal(response.headers.get("set-cookie"), null);
    } finally { worker.pin_hash = originalHash; }
  });
  await t.test("CSRF rejects missing/null/foreign/prefix origins and missing/wrong custom headers", async () => {
    const session = makeSession();
    for (const path of ["/auth/login", "/auth/refresh", "/auth/logout"]) {
      for (const badOrigin of ["", "null", "https://evil.example", `${origin}.evil.example`]) {
        const response = await request(path, { sessionId: session.id }, {
          Origin: badOrigin, Cookie: cookie(session.token), "X-Forwarded-Host": "keeptimer.example", Referer: `${origin}/`,
        });
        assert.equal(response.status, 403);
        assert.equal(response.headers.get("set-cookie"), null);
        assert.equal(response.headers.get("access-control-allow-origin"), null);
        assertNoStore(response);
      }
      for (const marker of ["", "0", "1, 1"]) {
        assert.equal((await request(path, { sessionId: session.id }, { "X-KeepTimer-CSRF": marker })).status, 403);
      }
    }
    assert.equal(writes.length, 0);
  });
  await t.test("classic HTML form, text/plain, malformed JSON and oversized bodies fail safely", async () => {
    for (const [contentType, body, status] of [["application/x-www-form-urlencoded", "username=worker&pin=1234", 415],
      ["text/plain", "{}", 415], ["multipart/form-data; boundary=x", "test", 415],
      ["application/json", "{", 400], ["application/json", JSON.stringify({ padding: "x".repeat(110000) }), 413]]) {
      const response = await originalFetch(`${base}/auth/login`, {
        method: "POST", headers: { ...csrfHeaders, "Content-Type": contentType }, body,
      });
      assert.equal(response.status, status);
      assertNoStore(response);
      assert.equal(response.headers.get("set-cookie"), null);
    }
    for (const body of [{ username: {}, pin: "1234" }, { username: "worker", pin: 1234 }, { username: "worker", pin: "1234", role: "superadmin" }]) {
      assert.equal((await request("/auth/login", body)).status, 400);
    }
  });
  await t.test("preflight is origin-scoped; Bearer routes and Telegram webhook need no CSRF header", async () => {
    const preflight = await originalFetch(`${base}/auth/refresh`, { method: "OPTIONS", headers: {
      Origin: origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,x-keeptimer-csrf",
    } });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), origin);
    assert.equal(preflight.headers.get("access-control-allow-credentials"), "true");
    assertNoStore(preflight);
    assert.equal((await originalFetch(`${base}/auth/login`, { headers: { Origin: origin } })).status, 405);
    assert.equal((await originalFetch(`${base}/auth/refresh`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } })).status, 403);
    assert.equal((await originalFetch(`${base}/health`)).status, 200);
    assert.equal((await originalFetch(`${base}/webhook`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status, 200);
    assert.equal((await bearerRequest("/telegram/control", makeSession())).status, 200);
  });
  await t.test("local reverse proxy preserves browser Origin, cookie scope and Set-Cookie", async sub => {
    const forwarded = [];
    const proxy = createServer((req, res) => {
      const path = req.url.replace(/^\/api\/auth(?=\/)/, "/auth");
      forwarded.push({ path, origin: req.headers.origin });
      const upstream = httpRequest(`${base}${path}`, { method: req.method, headers: {
        ...req.headers, host: new URL(base).host, "x-forwarded-for": `198.51.100.${group}`,
      } }, incoming => { res.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(res); });
      upstream.on("error", () => res.writeHead(502).end());
      req.pipe(upstream);
    }).listen(0, "127.0.0.1");
    await once(proxy, "listening");
    sub.after(async () => { proxy.closeAllConnections(); await new Promise(done => proxy.close(done)); });
    const proxyBase = `http://127.0.0.1:${proxy.address().port}`;
    const response = await originalFetch(`${proxyBase}/api/auth/login`, { method: "POST", headers: csrfHeaders,
      body: JSON.stringify({ username: "worker", pin: "1234" }) });
    assert.equal(response.status, 200);
    const body = await response.json();
    const header = response.headers.get("set-cookie");
    assert.match(header, /Path=\/api\/auth/);
    assert.doesNotMatch(header, /Domain=/);
    assertNoStore(response);
    const refreshed = await originalFetch(`${proxyBase}/api/auth/refresh`, { method: "POST",
      headers: { ...csrfHeaders, Cookie: header.split(";")[0] }, body: JSON.stringify({ sessionId: body.sessionId }) });
    assert.equal(refreshed.status, 200);
    assert.deepEqual(forwarded, [{ path: "/auth/login", origin }, { path: "/auth/refresh", origin }]);
    assert.equal((await request("/auth/refresh", { sessionId: body.sessionId }, {
      Origin: "http://localhost:5173", Cookie: header.split(";")[0], "X-Forwarded-Host": "anything.example",
    })).status, 200);
  });
  await t.test("native login uses existing JWT lifetimes, DB identity and hashed session storage", async () => {
    const response = await nativeRequest("login", { username: "worker", pin: "1234" });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), ["accessToken", "refreshToken", "sessionId", "user"]);
    const access = auth.verifyToken(body.accessToken), refresh = auth.verifyToken(body.refreshToken);
    assert.equal(access.type, "access");
    assert.equal(refresh.type, "refresh");
    assert.equal(access.exp - access.iat, 900);
    assert.equal(refresh.exp - refresh.iat, 30 * 24 * 60 * 60);
    assert.equal(access.sessionId, body.sessionId);
    assert.equal(refresh.sessionId, body.sessionId);
    assert.equal(refresh.id, users.get("worker").id);
    assert.deepEqual(body.user, { id: refresh.id, username: "worker", role: "worker", workspace_id: workspaceId });
    assert.equal(sessions.get(body.sessionId).refresh_token_hash, auth.hashToken(body.refreshToken));
    assert.equal((await bearerRequest("/telegram/control", { access: body.accessToken })).status, 200);
  });
  await t.test("native refresh returns only access/sessionId without rotation and ignores a different cookie", async () => {
    const session = makeSession(), other = makeSession();
    const response = await nativeSession("refresh", session, undefined, { Cookie: cookie(other.token) });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), ["accessToken", "sessionId"]);
    assert.equal(body.sessionId, session.id);
    assert.equal(auth.verifyToken(body.accessToken).sessionId, session.id);
    assert.equal(sessions.get(session.id).refresh_token_hash, auth.hashToken(session.token));
    assert.equal((await nativeSession("refresh", session)).status, 200, "same credential remains usable");
  });
  await t.test("native logout revokes/disconnects only its session and leaves the other socket usable", async () => {
    const session = makeSession(), other = makeSession();
    const socket = await connectSocket(session.access), otherSocket = await connectSocket(other.access);
    assert.match(socket.packet, /^40/);
    assert.match(otherSocket.packet, /^40/);
    const response = await nativeSession("logout", session, undefined, { Cookie: cookie(other.token) });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, sessionId: session.id });
    assert.ok(sessions.get(session.id).revoked_at);
    assert.equal(sessions.get(other.id).revoked_at, null);
    assert.equal(writes.length, 1);
    assert.deepEqual(writes[0].ids, [session.id]);
    await assertDisconnected(socket);
    // A live Engine.IO session still accepts polling transport packets.
    assert.equal((await originalFetch(otherSocket.endpoint, { method: "POST", body: '42["native-session-alive"]' })).status, 200);
    assert.equal((await nativeSession("refresh", other)).status, 200);
    assert.equal((await nativeSession("refresh", session)).status, 401);
    assert.equal((await nativeSession("logout", session)).status, 401);
  });
  await t.test("native rejects missing/malformed/expired/forged/access credentials even with valid cookie", async () => {
    const session = makeSession();
    const payload = { id: users.get("worker").id, sessionId: session.id, type: "refresh" };
    const expired = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: -1 });
    const forged = jwt.sign(payload, "wrong-secret");
    for (const action of ["refresh", "logout"]) {
      for (const value of [null, "", "Basic abc", "Bearer broken", `Bearer ${expired}`, `Bearer ${forged}`,
        `Bearer ${session.access}`, `Bearer ${session.token}, Bearer ${session.token}`]) {
        const response = await nativeRequest(action, { sessionId: session.id }, {
          Cookie: cookie(session.token), ...(value === null ? {} : { Authorization: value }),
          "X-Native": "true", "User-Agent": "KeepTimer Android",
        });
        assert.equal(response.status, 401);
      }
    }
    assert.equal(writes.length, 0);
  });
  await t.test("native rejects duplicate Authorization headers on the wire", async () => {
    const session = makeSession();
    const response = await new Promise((resolve, reject) => {
      const req = httpRequest(`${base}/auth/native/refresh`, { method: "POST", headers: {
        "Content-Type": "application/json", Authorization: [`Bearer ${session.token}`, `Bearer ${session.token}`],
      } }, res => { res.resume(); res.on("end", () => resolve(res)); });
      req.on("error", reject);
      req.end(JSON.stringify({ sessionId: session.id }));
    });
    assert.equal(response.statusCode, 401);
    assert.equal(response.headers["set-cookie"], undefined);
    assert.equal(response.headers["cache-control"], "no-store");
  });
  await t.test("native session mismatch is 409 with no mutation", async () => {
    const session = makeSession(), other = makeSession();
    for (const action of ["refresh", "logout"]) {
      const response = await nativeSession(action, session, { sessionId: other.id });
      assert.equal(response.status, 409);
      assert.equal((await response.json()).code, "AUTH_SESSION_CHANGED");
    }
    assert.equal(writes.length, 0);
    assert.equal(sessions.get(session.id).revoked_at, null);
    assert.equal(sessions.get(other.id).revoked_at, null);
  });
  await t.test("delayed native A logout cannot revoke a newly logged-in account B", async () => {
    const a = makeSession();
    const hold = { reached: deferred(), release: deferred() };
    heldUpdate = hold;
    const pending = nativeSession("logout", a);
    await hold.reached.promise;
    let b;
    try {
      const response = await nativeRequest("login", { username: "manager", pin: "1234" });
      assert.equal(response.status, 200);
      b = await response.json();
    } finally { hold.release.resolve(); }
    assert.equal((await pending).status, 200);
    assert.ok(sessions.get(a.id).revoked_at);
    assert.equal(sessions.get(b.sessionId).revoked_at, null);
    assert.equal((await nativeSession("refresh", { id: b.sessionId, token: b.refreshToken })).status, 200);
  });
  await t.test("native refresh/logout enforce session existence, hash, owner and revocation", async () => {
    for (const mutate of [row => { sessions.delete(row.id); }, row => { row.refresh_token_hash = "wrong"; },
      row => { row.user_id = users.get("manager").id; }, row => { row.revoked_at = new Date().toISOString(); }]) {
      const session = makeSession();
      mutate(sessions.get(session.id));
      for (const action of ["refresh", "logout"]) assert.equal((await nativeSession(action, session)).status, 401);
    }
    assert.equal(writes.length, 0);
  });
  await t.test("native disabled user cannot login or refresh, including DB closure races", async () => {
    const session = makeSession();
    users.get("worker").disabled_at = new Date().toISOString();
    assert.equal((await nativeRequest("login", { username: "worker", pin: "1234" })).status, 401);
    assert.equal((await nativeSession("refresh", session)).status, 401);
    users.get("worker").disabled_at = null;
    failure = { table: "sessions", method: "POST", code: "P0001", message: "KEEPTIMER_ACCOUNT_DISABLED", status: 400 };
    assert.equal((await nativeRequest("login", { username: "worker", pin: "1234" })).status, 401);
    failure = { table: "keeptimer_refresh_session", method: "POST", code: "P0001", message: "KEEPTIMER_ACCOUNT_DISABLED", status: 400 };
    assert.equal((await nativeSession("refresh", session)).status, 401);
  });
  await t.test("force logout and account closure invalidate native refresh through existing authority", async () => {
    const admin = makeSession("superadmin"), session = makeSession();
    assert.equal((await bearerRequest(`/users/${users.get("worker").id}/force-logout`, admin)).status, 200);
    assert.equal((await nativeSession("refresh", session)).status, 401);
    const second = makeSession();
    assert.equal((await bearerRequest(`/users/${users.get("worker").id}`, admin, "DELETE")).status, 200);
    assert.equal((await nativeSession("refresh", second)).status, 401);
  });
  await t.test("native DB errors are 503, not logout success or invalid-credential responses", async () => {
    const session = makeSession();
    for (const [action, table, method] of [["login", "users", "GET"], ["login", "sessions", "POST"],
      ["refresh", "sessions", "GET"], ["refresh", "keeptimer_refresh_session", "POST"],
      ["logout", "sessions", "GET"], ["logout", "sessions", "PATCH"]]) {
      failure = { table, method };
      const response = action === "login" ? await nativeRequest(action, { username: "worker", pin: "1234" }) :
        await nativeSession(action, session);
      assert.equal(response.status, 503);
    }
    assert.equal(sessions.get(session.id).revoked_at, null);
  });
  await t.test("native errors never log or reflect PIN, body, Authorization, tokens or upstream exceptions", async () => {
    const session = makeSession(), secret = "PRIVATE-NATIVE-BODY-AND-HEADER";
    const messages = [], originals = {};
    for (const method of ["log", "error", "warn", "info", "debug"]) {
      originals[method] = console[method];
      console[method] = (...args) => messages.push(args.map(String).join(" "));
    }
    const originalHash = users.get("worker").pin_hash;
    try {
      const check = async response => {
        assert.equal(response.status, 503);
        const text = await response.text();
        for (const value of [secret, session.token, session.access, "Bearer "]) assert.ok(!text.includes(value));
      };
      failure = { table: "sessions", method: "GET", message: `${secret} Bearer ${session.token}` };
      await check(await nativeSession("refresh", session));
      await check(await nativeSession("logout", session));
      failure = null;
      users.get("worker").pin_hash = 42; // bcrypt exception must be sanitized.
      await check(await nativeRequest("login", { username: "worker", pin: secret }, { Authorization: `Bearer ${session.token}` }));
      users.get("worker").pin_hash = originalHash;
      const success = await nativeRequest("login", { username: "worker", pin: "1234" });
      assert.equal(success.status, 200);
      const credentials = await success.json();
      for (const value of [secret, session.token, session.access, credentials.accessToken, credentials.refreshToken, "Bearer ", "1234"]) {
        assert.ok(messages.every(message => !message.includes(value)));
      }
      assert.ok(messages.some(message => message.includes("[native auth]")), "unexpected error handler was exercised");
    } finally {
      users.get("worker").pin_hash = originalHash;
      for (const method of Object.keys(originals)) console[method] = originals[method];
    }
  });
  await t.test("native body contract rejects extra token fields, invalid session IDs and non-objects", async () => {
    const session = makeSession();
    for (const action of ["refresh", "logout"]) {
      for (const body of [null, [], {}, { sessionId: "bad" }, { sessionId: 1 },
        { sessionId: session.id, refreshToken: session.token }]) {
        assert.equal((await nativeSession(action, session, body)).status, 400);
      }
    }
    for (const body of [null, [], {}, { username: {}, pin: "1234" }, { username: "worker", pin: 1234 },
      { username: "worker", pin: "1234", role: "superadmin" }]) {
      assert.equal((await nativeRequest("login", body)).status, 400);
    }
    assert.equal(writes.length, 0);
  });
  await t.test("native parser rejects wrong content type, malformed JSON and oversized body without reflection", async () => {
    for (const action of ["login", "refresh", "logout"]) {
      for (const [contentType, body, status] of [["text/plain", "private-body", 415],
        ["application/x-www-form-urlencoded", "pin=private-body", 415], ["application/json", '{"pin":"private-body",', 400],
        ["application/json", JSON.stringify({ pin: "private-body".repeat(10000) }), 413]]) {
        const response = await originalFetch(`${base}/auth/native/${action}`, {
          method: "POST", headers: { "Content-Type": contentType }, body,
        });
        assert.equal(response.status, status);
        assertNoStore(response);
        assert.equal(response.headers.get("set-cookie"), null);
        assert.ok(!(await response.text()).includes("private-body"));
      }
    }
  });
  await t.test("native rejects every supplied Origin and preflight without granting CORS", async () => {
    const session = makeSession();
    for (const action of ["login", "refresh", "logout"]) {
      for (const suppliedOrigin of [origin, "https://localhost", "https://evil.example", "null", ""]) {
        const response = await nativeSession(action, session, undefined, { Origin: suppliedOrigin });
        assert.equal(response.status, 403);
        assert.equal((await response.json()).code, "AUTH_ORIGIN_REJECTED");
        const preflight = await originalFetch(`${base}/auth/native/${action}`, { method: "OPTIONS", headers: {
          Origin: suppliedOrigin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type",
        } });
        assert.equal(preflight.status, 403);
        assertNoStore(preflight);
        assert.equal(preflight.headers.get("access-control-allow-origin"), null);
      }
      for (const method of ["GET", "OPTIONS"]) {
        const response = await originalFetch(`${base}/auth/native/${action}`, { method });
        assert.equal(response.status, 405);
        assert.equal(response.headers.get("allow"), "POST");
        assertNoStore(response);
      }
    }
    assert.equal(writes.length, 0);
  });
  await t.test("native and web share username failures even across different IPs", async () => {
    const username = "native-web-lockout";
    users.set(username, { ...users.get("worker"), username });
    try {
      for (let i = 0; i < 5; i++) {
        const headers = { "X-Forwarded-For": `192.0.2.${i + 1}` };
        const body = { username, pin: "wrong" };
        const response = i % 2 ? await request("/auth/login", body, headers) : await nativeRequest("login", body, headers);
        assert.equal(response.status, 401);
      }
      assert.equal((await nativeRequest("login", { username, pin: "1234" }, { "X-Forwarded-For": "192.0.2.6" })).status, 429);
      assert.equal((await request("/auth/login", { username, pin: "1234" }, { "X-Forwarded-For": "192.0.2.7" })).status, 429);
      assert.equal(writes.length, 0);
    } finally { users.delete(username); }
  });
  for (const startNative of [false, true]) await t.test(`web/native switching shares IP limit (native first: ${startNative})`, async () => {
    for (let i = 0; i < 12; i++) {
      const headers = { "X-Forwarded-For": `203.0.113.${i + 1}, 198.51.100.${group}`, "X-Real-IP": `203.0.113.${i + 1}` };
      const body = { username: `native-ip-${group}-${i}`, pin: "wrong" };
      const response = Boolean(i % 2) === startNative ? await request("/auth/login", body, headers) : await nativeRequest("login", body, headers);
      assert.equal(response.status, i < 10 ? 401 : 429);
      assertNoStore(response);
    }
  });
  await t.test("wrong PIN and username lockout are retained", async () => {
    for (let i = 0; i < 5; i++) {
      const response = await request("/auth/login", { username: "manager", pin: "wrong" });
      assert.equal(response.status, 401);
      assert.equal(response.headers.get("set-cookie"), null);
    }
    const response = await login("manager");
    assert.equal(response.status, 429);
    assertNoStore(response);
    assert.equal(writes.length, 0);
  });
  await t.test("login IP limit cannot be bypassed by spoofing left-most forwarding headers", async () => {
    for (let i = 0; i < 11; i++) {
      const response = await request("/auth/login", { username: `missing-${i}`, pin: "wrong" }, {
        "X-Forwarded-For": `203.0.113.${i + 1}, 198.51.100.${group}`,
        "X-Real-IP": `203.0.113.${i + 1}`, "X-Forwarded-Host": "untrusted.example",
      });
      assert.equal(response.status, i < 10 ? 401 : 429);
      assertNoStore(response);
    }
  });
});
