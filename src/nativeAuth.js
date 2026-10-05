// Native transport is deliberately outside browser cookie/CORS authentication.
export function nativeAuthGuard(req, res, next) {
  req.nativeAuth = true;
  res.set({
    "Cache-Control": "no-store",
    "CDN-Cache-Control": "no-store",
    "Vercel-CDN-Cache-Control": "no-store",
    Pragma: "no-cache",
  });
  res.vary("Origin");
  // Defense in depth against browser use, NOT proof of a native device.
  // Credential and DB/session verification remain mandatory without Origin.
  if (req.headers.origin !== undefined) {
    return res.status(403).json({ error: "İzin verilmeyen Origin", code: "AUTH_ORIGIN_REJECTED" });
  }
  if (req.method !== "POST") {
    return res.status(405).set("Allow", "POST").json({ error: "Yöntem desteklenmiyor", code: "AUTH_METHOD_REJECTED" });
  }
  if (!req.is("application/json")) {
    return res.status(415).json({ error: "application/json gerekli", code: "AUTH_CONTENT_TYPE_REJECTED" });
  }
  next();
}

export function readBearerRefresh(req) {
  // Node may discard duplicate Authorization headers. Reject ambiguity before
  // reading the normalized value; never inspect cookies for this transport.
  let count = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === "authorization") count++;
  }
  const value = req.headers.authorization;
  if (count !== 1 || typeof value !== "string" || value.length > 4096) return null;
  return /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(value)?.[1] ?? null;
}

export function nativeAuthErrorHandler(error, req, res, next) {
  if (!req.nativeAuth || res.headersSent) return next(error);
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Geçersiz JSON", code: "AUTH_BODY_INVALID" });
  }
  if (error.status === 413 || error.status === 415) {
    return res.status(error.status).json({ error: "İstek gövdesi desteklenmiyor", code: "AUTH_BODY_INVALID" });
  }
  // Never log the exception, Authorization, tokens or request body.
  console.error("[native auth] İşlem tamamlanamadı");
  return res.status(503).json({ error: "Sunucu geçici olarak erişilemiyor", code: "AUTH_UNAVAILABLE" });
}
