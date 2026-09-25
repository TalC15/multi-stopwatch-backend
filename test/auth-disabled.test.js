import test from "node:test";
import assert from "node:assert/strict";
import { ids } from "./support/database.js";

// Exercise the actual access-token and socket authentication helper with a
// minimal PostgREST response. The DB transaction tests cover session writes.
test("disabled account's existing access token is rejected", async () => {
  process.env.JWT_SECRET = "local-only-company-deactivation-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-only-test-key";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (request) => {
    const pathname = new URL(request.url ?? request).pathname;
    const response = pathname.endsWith("/users")
      ? { id: ids.worker, username: "worker", role: "worker",
          workspace_id: ids.company, disabled_at: "2026-09-25T00:00:00Z" }
      : { id: ids.session, revoked_at: null };
    return new Response(JSON.stringify(response), {
      headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const { generateAccessToken, validateAccessToken } = await import("../src/auth.js");
    const result = await validateAccessToken(generateAccessToken({ id: ids.worker }, ids.session));
    assert.equal(result.ok, false);
    assert.equal(result.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
