import test from "node:test";
import assert from "node:assert/strict";

test("superadmin creation does not print its PIN or credential material", async () => {
  process.env.JWT_SECRET = "local-log-test-secret";
  process.env.SUPABASE_URL = "http://127.0.0.1:54321";
  process.env.SUPABASE_SERVICE_KEY = "local-log-test-service-key";
  process.env.SUPERADMIN_PIN = "local-private-bootstrap-pin";
  const originalFetch = globalThis.fetch;
  const originalLog = console.log;
  const messages = [];
  let inserted;
  console.log = (...args) => messages.push(args.join(" "));
  globalThis.fetch = async (request, options = {}) => {
    assert.equal(new URL(request.url ?? request).origin, "http://127.0.0.1:54321");
    if (options.method === "POST") inserted = JSON.parse(options.body);
    return new Response("null", { headers: { "Content-Type": "application/json" } });
  };
  try {
    const { createSuperAdminIfNotExists, verifyPin } = await import("../src/auth.js");
    await createSuperAdminIfNotExists();
    assert.equal(inserted.username, "admin");
    assert.equal(await verifyPin(process.env.SUPERADMIN_PIN, inserted.pin_hash), true);
    assert.ok(messages.some(message => message.includes("Superadmin oluşturuldu")));
    for (const secret of [process.env.SUPERADMIN_PIN, process.env.JWT_SECRET, process.env.SUPABASE_SERVICE_KEY, inserted.pin_hash]) {
      assert.ok(messages.every(message => !message.includes(secret)));
    }
  } finally {
    globalThis.fetch = originalFetch;
    console.log = originalLog;
  }
});
