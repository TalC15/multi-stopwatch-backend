import cors from "cors";

export const REFRESH_COOKIE_NAME = "__Secure-keeptimer-refresh";
export const REFRESH_COOKIE_OPTIONS = Object.freeze({
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  // Browser-facing proxy path, NOT the upstream Express /auth path.
  path: "/api/auth",
});

export function parseAuthOrigins(value = "") {
  const origins = value.split(",").map(value => value.trim()).filter(Boolean);
  for (const origin of origins) {
    const url = new URL(origin);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.origin !== origin || url.username || url.password || url.hostname.includes("*") ||
        (url.protocol !== "https:" && !(local && url.protocol === "http:"))) {
      throw new Error("AUTH_ALLOWED_ORIGINS must contain exact HTTPS origins (HTTP loopback allowed)");
    }
  }
  return new Set(origins);
}

export function createWebAuthGuard(origins) {
  const authCors = cors({
    origin: (origin, callback) => callback(null, origins.has(origin)),
    credentials: true,
    methods: ["POST"],
    allowedHeaders: ["Content-Type", "X-KeepTimer-CSRF"],
  });
  return (req, res, next) => {
    req.webAuth = true;
    res.set({
      "Cache-Control": "no-store",
      "CDN-Cache-Control": "no-store",
      "Vercel-CDN-Cache-Control": "no-store",
      Pragma: "no-cache",
    });
    res.vary("Origin");
    if (!origins.size) {
      return res.status(503).json({ error: "Web oturumu yapılandırılmamış", code: "AUTH_NOT_CONFIGURED" });
    }
    // Never infer an allowed origin from Host, Referer or forwarded headers.
    if (!origins.has(req.get("Origin"))) {
      return res.status(403).json({ error: "İzin verilmeyen Origin", code: "AUTH_ORIGIN_REJECTED" });
    }
    if (req.method === "OPTIONS") {
      if (req.get("Access-Control-Request-Method") !== "POST") {
        return res.status(405).set("Allow", "POST, OPTIONS").json({ error: "Yöntem desteklenmiyor", code: "AUTH_METHOD_REJECTED" });
      }
      return authCors(req, res, next);
    }
    return authCors(req, res, () => {
      if (req.method !== "POST") {
        return res.status(405).set("Allow", "POST, OPTIONS").json({ error: "Yöntem desteklenmiyor", code: "AUTH_METHOD_REJECTED" });
      }
      if (!req.is("application/json")) {
        return res.status(415).json({ error: "application/json gerekli", code: "AUTH_CONTENT_TYPE_REJECTED" });
      }
      if (req.get("X-KeepTimer-CSRF") !== "1") {
        return res.status(403).json({ error: "CSRF başlığı gerekli", code: "AUTH_CSRF_REJECTED" });
      }
      next();
    });
  };
}

// Reject duplicate cookies instead of selecting an ambiguous session.
export function readRefreshCookie(req) {
  const values = [];
  for (const part of (req.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== REFRESH_COOKIE_NAME) continue;
    values.push(part.slice(separator + 1).trim());
  }
  if (values.length !== 1 || !values[0] || values[0].length > 4096) return null;
  try { return decodeURIComponent(values[0]); } catch { return null; }
}

export function setRefreshCookie(res, token, expiresAt) {
  res.cookie(REFRESH_COOKIE_NAME, token, {
    ...REFRESH_COOKIE_OPTIONS,
    expires: new Date(expiresAt * 1000),
  });
}

export function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE_NAME, REFRESH_COOKIE_OPTIONS);
}

export function webAuthErrorHandler(error, req, res, next) {
  if (!req.webAuth || res.headersSent) return next(error);
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Geçersiz JSON", code: "AUTH_BODY_INVALID" });
  }
  if (error.status === 413 || error.status === 415) {
    return res.status(error.status).json({ error: "İstek gövdesi desteklenmiyor", code: "AUTH_BODY_INVALID" });
  }
  // No request body, cookie or upstream error object is logged here.
  console.error("[web auth] İşlem tamamlanamadı");
  return res.status(503).json({ error: "Sunucu geçici olarak erişilemiyor", code: "AUTH_UNAVAILABLE" });
}
