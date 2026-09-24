import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { createServer } from "http";
import { Server } from "socket.io";
import { scheduleTimer, cancelTimer } from "./timers.js";
import { sendTelegramMessage } from "./telegram.js";
import {
  authenticate,
  authorize,
  createSuperAdminIfNotExists,
  hashPin,
  verifyPin,
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  hashToken,
  validateAccessToken,
} from "./auth.js";
import supabase from "./db.js";

dotenv.config();

const app = express();
app.use(cors());
app.set("trust proxy", 1);
app.use(express.json());

// HTTP server oluştur — Socket.io bunun üzerine kurulacak
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: "*" }, // şimdilik herkese açık, ileride kısıtlarız
});

// Superadmin ilk kurulumda oluştur
createSuperAdminIfNotExists();

// ─── Login güvenliği ────────────────────────────────────────────────────────

// IP bazlı: aynı IP'den 15 dakikada en fazla 10 login denemesi
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const resetMs = req.rateLimit?.resetTime
      ? req.rateLimit.resetTime.getTime() - Date.now()
      : 15 * 60 * 1000;
    const resetMin = Math.max(1, Math.ceil(resetMs / 60000));
    res.status(429).json({
      error: `Çok fazla deneme yapıldı. Lütfen ${resetMin} dakika sonra tekrar deneyin.`,
    });
  },
});

// Kullanıcı adı bazlı: aynı kullanıcı adına 15 dakikada en fazla 5 başarısız deneme
const failedLoginAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;

function isLockedOut(username) {
  const entry = failedLoginAttempts.get(username);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > LOCKOUT_WINDOW_MS) {
    failedLoginAttempts.delete(username);
    return false;
  }
  return entry.count >= MAX_FAILED_ATTEMPTS;
}

function recordFailedAttempt(username) {
  const entry = failedLoginAttempts.get(username);
  if (!entry || Date.now() - entry.firstAttempt > LOCKOUT_WINDOW_MS) {
    failedLoginAttempts.set(username, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}

function clearFailedAttempts(username) {
  failedLoginAttempts.delete(username);
}

// ─── Auth Routes ──────────────────────────────────────────────────────────

// Giriş
app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: "Kullanıcı adı ve PIN gerekli" });
  }

  if (isLockedOut(username)) {
    return res.status(429).json({
      error:
        "Çok fazla başarısız deneme. Lütfen 15 dakika sonra tekrar deneyin.",
    });
  }

  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .single();

  // Kullanıcı bulunamadı ve PIN hatalı aynı mesajı döner (enumeration önleme)
  if (error || !user) {
    recordFailedAttempt(username);
    return res.status(401).json({ error: "Kullanıcı adı veya PIN hatalı" });
  }

  const pinValid = await verifyPin(pin, user.pin_hash);
  if (!pinValid) {
    recordFailedAttempt(username);
    return res.status(401).json({ error: "Kullanıcı adı veya PIN hatalı" });
  }

  clearFailedAttempts(username);

  // Yeni bir oturum (session) kaydı oluştur
  const sessionId = crypto.randomUUID();
  const accessToken = generateAccessToken(user, sessionId);
  const refreshToken = generateRefreshToken(user, sessionId);

  const { error: sessionError } = await supabase.from("sessions").insert({
    id: sessionId,
    user_id: user.id,
    refresh_token_hash: hashToken(refreshToken),
    user_agent: req.headers["user-agent"] || null,
  });

  if (sessionError) {
    console.error("[auth/login] oturum kaydı oluşturulamadı:", sessionError);
    return res.status(500).json({ error: "Giriş yapılamadı, tekrar deneyin" });
  }

  res.json({
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      workspace_id: user.workspace_id,
    },
  });
});

// Token yenile
app.post("/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token gerekli" });
  }

  const decoded = verifyToken(refreshToken);
  if (!decoded || decoded.type !== "refresh" || !decoded.sessionId) {
    return res.status(401).json({ error: "Geçersiz refresh token" });
  }

  const { data: session, error } = await supabase
    .from("sessions")
    .select("id, user_id, refresh_token_hash, revoked_at")
    .eq("id", decoded.sessionId)
    .eq("user_id", decoded.id)
    .single();

  if (error) {
    // "Satır bulunamadı" → gerçekten geçersiz oturum → 401
    // Başka türlü hata (bağlantı vb.) → geçici altyapı sorunu → 503
    if (error.code === "PGRST116") {
      return res
        .status(401)
        .json({ error: "Oturum bulunamadı, tekrar giriş yapın" });
    }
    console.error("[auth/refresh] Supabase hatası:", error);
    return res.status(503).json({ error: "Sunucu geçici olarak erişilemiyor" });
  }

  if (!session) {
    return res
      .status(401)
      .json({ error: "Oturum bulunamadı, tekrar giriş yapın" });
  }

  if (session.revoked_at) {
    return res
      .status(401)
      .json({ error: "Oturum sonlandırılmış, tekrar giriş yapın" });
  }

  if (session.refresh_token_hash !== hashToken(refreshToken)) {
    return res.status(401).json({ error: "Geçersiz refresh token" });
  }

  await supabase
    .from("sessions")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", decoded.sessionId);

  const accessToken = generateAccessToken(
    { id: decoded.id },
    decoded.sessionId,
  );
  res.json({ accessToken });
});

// Çıkış — mevcut oturumu iptal et
app.post("/auth/logout", async (req, res) => {
  const { refreshToken } = req.body ?? {};

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token gerekli" });
  }

  const decoded = verifyToken(refreshToken);

  if (
    !decoded ||
    decoded.type !== "refresh" ||
    !decoded.id ||
    !decoded.sessionId
  ) {
    return res.status(401).json({ error: "Geçersiz refresh token" });
  }

  const { data: session, error: sessionError } = await supabase
    .from("sessions")
    .select("id, user_id, refresh_token_hash, revoked_at")
    .eq("id", decoded.sessionId)
    .eq("user_id", decoded.id)
    .single();

  if (sessionError) {
    if (sessionError.code === "PGRST116") {
      return res.status(401).json({ error: "Oturum bulunamadı" });
    }

    console.error("[auth/logout] Session okunamadı:", sessionError);

    return res.status(503).json({
      error: "Sunucu geçici olarak erişilemiyor",
    });
  }

  if (!session) {
    return res.status(401).json({ error: "Oturum bulunamadı" });
  }

  if (session.refresh_token_hash !== hashToken(refreshToken)) {
    return res.status(401).json({ error: "Geçersiz refresh token" });
  }

  // Logout idempotent olsun.
  if (session.revoked_at) {
    io.in(`session-${session.id}`).disconnectSockets(true);

    return res.json({ success: true });
  }

  const { error: revokeError } = await supabase
    .from("sessions")
    .update({
      revoked_at: new Date().toISOString(),
    })
    .eq("id", session.id)
    .eq("user_id", decoded.id)
    .is("revoked_at", null);

  if (revokeError) {
    console.error("[auth/logout] Session revoke edilemedi:", revokeError);

    return res.status(503).json({
      error: "Çıkış işlemi tamamlanamadı",
    });
  }

  // DB session artık geçersiz.
  // Aynı login session'ına bağlı açık socket'leri de
  // server tarafından anında kapat.
  io.in(`session-${session.id}`).disconnectSockets(true);

  return res.json({ success: true });
});

// ─── Kullanıcı Yönetimi (sadece superadmin ve manager) ───────────────────

// Kullanıcı oluştur
app.post(
  "/users/create",
  authenticate,
  authorize("superadmin", "manager"),
  async (req, res) => {
    const { username, pin, role, workspace_id } = req.body;
    if (username.length > 25 || pin.length > 25)
      return res.status(400).json({ error: "çok uzun isim veya PIN" });
    if (!username || !pin || !role) {
      return res.status(400).json({ error: "Eksik parametre" });
    }

    const usernameController = await supabase
      .from("users")
      .select("username")
      .eq("username", username)
      .single();

    if (usernameController.data)
      return res.status(400).json({ error: "Bu isim zaten mevcut" });

    if (req.user.role === "manager" && role !== "worker") {
      return res
        .status(403)
        .json({ error: "Manager sadece worker oluşturabilir" });
    }

    if (req.user.role === "manager" && !req.user.workspace_id) {
      return res.status(400).json({ error: "Önce bir workspace oluşturun" });
    }

    const assignedWorkspaceId =
      req.user.role === "superadmin"
        ? workspace_id || null
        : req.user.workspace_id;

    const pin_hash = await hashPin(pin);

    const { data, error } = await supabase
      .from("users")
      .insert({ username, pin_hash, role, workspace_id: assignedWorkspaceId })
      .select()
      .single();

    if (error)
      return res.status(500).json({ error: "Kullanıcı oluşturulamadı" });

    res.json({
      success: true,
      user: { id: data.id, username: data.username, role: data.role },
    });
  },
);

// ─── Workspace Routes ─────────────────────────────────────────────────────

// Workspace oluştur
app.post(
  "/workspace/create",
  authenticate,
  authorize("superadmin", "manager"),
  async (req, res) => {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Workspace adı gerekli" });
    }

    const inviteCode = Math.random().toString(36).substring(2, 8).toUpperCase();

    const { data: workspace, error } = await supabase
      .from("workspaces")
      .insert({ name, owner_id: req.user.id, invite_code: inviteCode })
      .select()
      .single();

    if (error)
      return res.status(500).json({ error: "Workspace oluşturulamadı" });

    await supabase
      .from("users")
      .update({ workspace_id: workspace.id })
      .eq("id", req.user.id);

    res.json({ success: true, workspace });
  },
);

// Davet kodu ile katıl
app.post("/workspace/join", authenticate, async (req, res) => {
  const { inviteCode } = req.body;

  if (!inviteCode) {
    return res.status(400).json({ error: "Davet kodu gerekli" });
  }

  const { data: workspace, error } = await supabase
    .from("workspaces")
    .select("id, name")
    .eq("invite_code", inviteCode.toUpperCase())
    .single();

  if (error || !workspace) {
    return res.status(404).json({ error: "Geçersiz davet kodu" });
  }

  await supabase
    .from("users")
    .update({ workspace_id: workspace.id })
    .eq("id", req.user.id);

  res.json({ success: true, workspace });
});

// Workspace bilgisi
app.get("/workspace", authenticate, async (req, res) => {
  if (!req.user.workspace_id) {
    return res.json({ workspace: null });
  }

  const { data, error } = await supabase
    .from("workspaces")
    .select("id, name, invite_code, owner_id,shared_mode_enabled")
    .eq("id", req.user.workspace_id)
    .single();

  if (error) return res.status(500).json({ error: "Workspace alınamadı" });
  res.json({ workspace: data });
});

// Shared mode aç/kapat (sadece manager/superadmin)
app.post(
  "/workspace/toggle-shared",
  authenticate,
  authorize("manager", "superadmin"),
  async (req, res) => {
    if (!req.user.workspace_id) {
      return res.status(400).json({ error: "Bir workspace'de değilsiniz" });
    }

    const { data: workspace } = await supabase
      .from("workspaces")
      .select("shared_mode_enabled")
      .eq("id", req.user.workspace_id)
      .single();

    const newValue = !workspace.shared_mode_enabled;

    const { error } = await supabase
      .from("workspaces")
      .update({ shared_mode_enabled: newValue })
      .eq("id", req.user.workspace_id);

    if (error) return res.status(500).json({ error: "Güncellenemedi" });
    res.json({ success: true, shared_mode_enabled: newValue });
  },
);

// ─── Telegram Routes ──────────────────────────────────────────────────────

// Telegram chat ID kaydet
app.post("/register", authenticate, async (req, res) => {
  const { chatId } = req.body;

  if (!chatId) {
    return res.status(400).json({ error: "chatId gerekli" });
  }

  try {
    const testUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    const params = new URLSearchParams({
      chat_id: chatId,
      text: "KeepTimer bildirimleri aktifleştirildi! ✓",
    });

    const telegramRes = await fetch(testUrl + "?" + params.toString());
    const telegramData = await telegramRes.json();

    if (!telegramData.ok) {
      return res.status(400).json({ error: "Geçersiz Chat ID" });
    }
  } catch {
    return res.status(500).json({ error: "Telegram doğrulaması başarısız" });
  }

  await supabase
    .from("users")
    .update({ telegram_chat_id: chatId })
    .eq("id", req.user.id);

  res.json({ success: true });
});

// Webhook — /id komutu
app.post("/webhook", async (req, res) => {
  const message = req.body?.message;
  if (!message) return res.sendStatus(200);

  const chatId = message.chat.id;
  const text = message.text;

  if (text === "/id" || text === "/start") {
    await sendTelegramMessage(chatId, `Chat ID'n: ${chatId}`);
  }

  res.sendStatus(200);
});

// Kullanıcıları listele
app.get(
  "/users",
  authenticate,
  authorize("superadmin", "manager"),
  async (req, res) => {
    let query = supabase
      .from("users")
      .select("id, username, role, created_at, workspace_id");

    if (req.user.role !== "superadmin") {
      if (!req.user.workspace_id) {
        return res.json({ users: [] });
      }
      query = query.eq("workspace_id", req.user.workspace_id);
    }

    const { data, error } = await query;

    if (error) return res.status(500).json({ error: "Kullanıcılar alınamadı" });
    res.json({ users: data });
  },
);

// Kullanıcı sil
app.delete(
  "/users/:id",
  authenticate,
  authorize("superadmin", "manager"),
  async (req, res) => {
    const { id } = req.params;

    if (id === req.user.id) {
      return res.status(400).json({ error: "Kendinizi silemezsiniz" });
    }

    const { error } = await supabase
      .from("users")
      .delete()
      .eq("id", id)
      .eq("workspace_id", req.user.workspace_id);

    if (error) return res.status(500).json({ error: "Kullanıcı silinemedi" });

    res.json({ success: true });
  },
);

// Kullanıcının oturumunu zorla kapat
app.post(
  "/users/:id/force-logout",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { id } = req.params;

    if (id === req.user.id) {
      return res
        .status(400)
        .json({ error: "Kendi oturumunuzu bu şekilde kapatamazsınız" });
    }

    const { data: targetUser, error: fetchError } = await supabase
      .from("users")
      .select("id")
      .eq("id", id)
      .single();

    if (fetchError || !targetUser) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }

    const { error } = await supabase
      .from("sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", id)
      .is("revoked_at", null);

    if (error) {
      return res.status(500).json({ error: "Oturum kapatılamadı" });
    }

    // Bu kullanıcıya ait tüm aktif login session socket'lerini
    // server tarafından anında kapat.
    io.in(`user-${id}`).disconnectSockets(true);

    res.json({ success: true });
  },
);

// Tüm kullanıcıları listele (sadece superadmin)
app.get(
  "/admin/users",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { data, error } = await supabase
      .from("users")
      .select("id, username, role, workspace_id, created_at");

    if (error) return res.status(500).json({ error: "Kullanıcılar alınamadı" });
    res.json({ users: data });
  },
);

// Kullanıcı güncelle (sadece superadmin)
app.patch(
  "/admin/users/:id",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { id } = req.params;
    const { username, role, workspace_id } = req.body;

    const { error } = await supabase
      .from("users")
      .update({ username, role, workspace_id })
      .eq("id", id);

    if (error)
      return res.status(500).json({ error: "Kullanıcı güncellenemedi" });
    res.json({ success: true });
  },
);

// Kullanıcı sil (sadece superadmin)
app.delete(
  "/admin/users/:id",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { id } = req.params;

    if (id === req.user.id) {
      return res.status(400).json({ error: "Kendinizi silemezsiniz" });
    }

    const { error } = await supabase.from("users").delete().eq("id", id);

    if (error) return res.status(500).json({ error: "Kullanıcı silinemedi" });
    res.json({ success: true });
  },
);

// Tüm workspace'leri listele (sadece superadmin)
app.get(
  "/admin/workspaces",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { data, error } = await supabase
      .from("workspaces")
      .select("id, name, owner_id, created_at,invite_code");

    if (error)
      return res.status(500).json({ error: "Workspace'ler alınamadı" });
    res.json({ workspaces: data });
  },
);

// Workspace'den ayrıl
app.post("/workspace/leave", authenticate, async (req, res) => {
  if (!req.user.workspace_id) {
    return res.status(400).json({ error: "Zaten bir workspace'de değilsiniz" });
  }

  if (req.user.role === "manager") {
    const { data: otherManagers } = await supabase
      .from("users")
      .select("id")
      .eq("workspace_id", req.user.workspace_id)
      .eq("role", "manager")
      .neq("id", req.user.id);

    if (!otherManagers || otherManagers.length === 0) {
      return res.status(400).json({
        error:
          "Workspace'de tek manager sizsiniz. Ayrılmadan önce başka bir manager atayın.",
      });
    }
  }

  await supabase
    .from("users")
    .update({ workspace_id: null })
    .eq("id", req.user.id);

  res.json({ success: true });
});

// Davet kodu yenile
app.post(
  "/workspace/refresh-invite",
  authenticate,
  authorize("manager", "superadmin"),
  async (req, res) => {
    if (!req.user.workspace_id) {
      return res.status(400).json({ error: "Bir workspace'de değilsiniz" });
    }

    const newInviteCode = Math.random()
      .toString(36)
      .substring(2, 8)
      .toUpperCase();

    const { error } = await supabase
      .from("workspaces")
      .update({ invite_code: newInviteCode })
      .eq("id", req.user.workspace_id);

    if (error)
      return res.status(500).json({ error: "Davet kodu yenilenemedi" });

    res.json({ success: true, invite_code: newInviteCode });
  },
);

// Workspace detayı (superadmin)
app.get(
  "/admin/workspaces/:id",
  authenticate,
  authorize("superadmin"),
  async (req, res) => {
    const { id } = req.params;

    const { data: workspace, error } = await supabase
      .from("workspaces")
      .select("id, name, invite_code, owner_id, created_at")
      .eq("id", id)
      .single();

    if (error || !workspace)
      return res.status(404).json({ error: "Workspace bulunamadı" });

    const { data: members } = await supabase
      .from("users")
      .select("id, username, role, created_at")
      .eq("workspace_id", id);

    res.json({ workspace, members: members || [] });
  },
);

// Timer oluştur ve DB'ye kaydet
app.post("/timers", authenticate, async (req, res) => {
  const { id, name, type, targetMinutes, isShared } = req.body;

  if (!id || !name || !type) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  const { data, error } = await supabase
    .from("timers")
    .insert({
      id,
      name,
      type,
      target_minutes: targetMinutes,
      is_shared: isShared || false,
      is_pay: false,
      accumulated_ms: 0,
      status: "idle",
      record_status: "active",
      workspace_id: req.user.workspace_id || null,
      created_by: req.user.id,
      user_id: req.user.id,
    })
    .select()
    .single();

  if (error) {
    console.error("[POST /timers] Timer oluşturma hatası:", error);
    return res.status(500).json({ error: "Timer oluşturulamadı" });
  }

  // Shared timer ancak DB'ye başarıyla yazıldıktan sonra workspace'e yayınlanır.
  if (data.is_shared && data.workspace_id) {
    const targetMs = Number(data.target_minutes || 0) * 60 * 1000;

    io.to(`workspace-${data.workspace_id}`).emit("timer-event", {
      event: "created",
      data: {
        id: data.id,
        name: data.name,
        targetMinutes: Number(data.target_minutes),
        type: data.type,
        isPay: Boolean(data.is_pay),
        isShared: true,
        status: data.status,
        startTime: null,
        accumulatedTime: Number(data.accumulated_ms || 0),
        elapsed: Number(data.accumulated_ms || 0),
        remaining: data.type === "down" ? targetMs : null,
        reachedTarget: false,
        pausedCount: Number(data.paused_count || 0),
      },
    });

    console.log(
      `[Socket] workspace-${data.workspace_id} → created yayınlandı (DB onaylı)`,
    );
  }

  res.json({ success: true, timer: data });
});

// Timer güncelle (status, isPay vb.)
app.patch("/timers/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  const allowed = [
    "status",
    "is_pay",
    "ends_at",
    "ended_at",
    "duration_ms",
    "paused_count",
    "record_status",
    "accumulated_ms",
  ];

  const filtered = Object.fromEntries(
    Object.entries(updates).filter(([key]) => allowed.includes(key)),
  );

  if (Object.keys(filtered).length === 0) {
    return res.status(400).json({ error: "Güncellenebilir alan yok" });
  }

  const { data: existing, error: fetchError } = await supabase
    .from("timers")
    .select(
      "id, user_id, workspace_id, is_shared, record_status, status, paused_count,type",
    )
    .eq("id", id)
    .eq("record_status", "active")
    .single();

  if (fetchError || !existing) {
    if (fetchError?.code !== "PGRST116") {
      console.error("[PATCH /timers/:id] Timer okuma hatası:", fetchError);
      return res.status(500).json({ error: "Timer okunamadı" });
    }

    return res.status(404).json({ error: "Timer bulunamadı" });
  }

  let canUpdate = false;

  if (req.user.role === "superadmin") {
    canUpdate = true;
  } else if (existing.is_shared) {
    canUpdate =
      Boolean(existing.workspace_id) &&
      existing.workspace_id === req.user.workspace_id;
  } else {
    canUpdate = existing.user_id === req.user.id;
  }

  if (!canUpdate) {
    return res.status(403).json({
      error: "Bu timer'ı güncelleme yetkiniz yok",
    });
  }

  // Count-Up hedefe ulaştığında timer tamamlanmış sayılmaz.
  // Eski client/APK "completed" gönderse bile DB'deki running state'i bozma.
  if (existing.type === "up" && filtered.status === "completed") {
    console.warn(
      `[PATCH /timers/:id] Count-Up completed isteği yok sayıldı: ${id}`,
    );

    delete filtered.status;
    delete filtered.ended_at;
    delete filtered.duration_ms;

    // Eski client sadece completion bilgisi gönderdiyse
    // yapılacak gerçek bir DB değişikliği kalmamıştır.
    if (Object.keys(filtered).length === 0) {
      return res.json({
        success: true,
        ignored: true,
        pausedCount: Number(existing.paused_count || 0),
      });
    }
  }

  // Shared timer'da paused_count değerine client karar veremez.
  if (existing.is_shared) {
    delete filtered.paused_count;

    // Gerçek bir running -> paused geçişiyse DB'deki sayaç 1 artar.
    if (filtered.status === "paused" && existing.status === "running") {
      filtered.paused_count = Number(existing.paused_count || 0) + 1;
    }
  } else if (filtered.paused_count !== undefined) {
    // Personal timer kendi local pause sayısını gönderir.
    const pausedCount = Number(filtered.paused_count);

    if (!Number.isInteger(pausedCount) || pausedCount < 0) {
      return res.status(400).json({
        error: "Geçersiz paused_count değeri",
      });
    }

    filtered.paused_count = pausedCount;
  }

  if (filtered.status === "running") {
    const { error: rpcError } = await supabase.rpc("set_started_at_if_null", {
      timer_id: id,
      new_started_at: new Date().toISOString(),
    });

    if (rpcError) {
      console.error("[PATCH /timers/:id] started_at RPC hatası:", rpcError);
      return res.status(500).json({ error: "Timer başlatılamadı" });
    }
  }

  const { data: updated, error: updateError } = await supabase
    .from("timers")
    .update(filtered)
    .eq("id", id)
    .eq("record_status", "active")
    .select("id, paused_count")
    .single();

  if (updateError || !updated) {
    if (updateError?.code === "PGRST116") {
      return res.status(409).json({
        error: "Timer artık aktif değil",
      });
    }

    console.error("[PATCH /timers/:id] Timer update hatası:", updateError);

    return res.status(500).json({
      error: "Timer güncellenemedi",
    });
  }

  if (existing.is_shared && existing.workspace_id) {
    const socketData = { id };

    if (filtered.status === "running" || filtered.status === "paused") {
      socketData.status = filtered.status;
      socketData.endsAt = filtered.ends_at ?? null;
      socketData.accumulatedTimeAtStart = filtered.accumulated_ms ?? 0;

      // Her cihaz DB'deki gerçek değeri alır.
      socketData.pausedCount = Number(updated.paused_count || 0);
    }

    // Countdown gerçekten tamamlandıysa bütün workspace'e anında bildir.
    if (existing.type === "down" && filtered.status === "completed") {
      socketData.status = "expired";
      socketData.endsAt = null;
      socketData.reachedTarget = true;
    }

    if (filtered.is_pay !== undefined) {
      socketData.isPay = filtered.is_pay;
    }

    if (Object.keys(socketData).length > 1) {
      io.to(`workspace-${existing.workspace_id}`).emit("timer-event", {
        event: "updated",
        data: socketData,
      });

      console.log(
        `[Socket] workspace-${existing.workspace_id} → updated yayınlandı (DB onaylı)`,
      );
    }
  }

  res.json({
    success: true,
    pausedCount: Number(updated.paused_count || 0),
  });
});

// Timer sil (gerçekten silmez, record_status = deleted yapar)
app.delete("/timers/:id", authenticate, async (req, res) => {
  const { id } = req.params;

  const { data: existing, error: fetchError } = await supabase
    .from("timers")
    .select("user_id, is_shared, workspace_id, record_status")
    .eq("id", id)
    .eq("record_status", "active")
    .single();

  if (fetchError || !existing) {
    return res.status(404).json({ error: "Timer bulunamadı" });
  }

  const canDelete =
    req.user.role === "superadmin" ||
    (existing.is_shared
      ? Boolean(existing.workspace_id) &&
        existing.workspace_id === req.user.workspace_id
      : existing.user_id === req.user.id);

  if (!canDelete) {
    return res.status(403).json({
      error: "Bu timer'ı silme yetkiniz yok",
    });
  }

  const { data: updated, error: updateError } = await supabase
    .from("timers")
    .update({ record_status: "deleted" })
    .eq("id", id)
    .eq("record_status", "active")
    .select("id, record_status")
    .single();

  if (updateError) {
    console.error("[DELETE /timers/:id] Timer update hatası:", updateError);

    return res.status(500).json({
      error: "Timer silinemedi",
      details: updateError.message,
    });
  }

  if (!updated || updated.record_status !== "deleted") {
    console.error("[DELETE /timers/:id] Timer güncellenmedi:", updated);

    return res.status(500).json({
      error: "Timer güncellemesi doğrulanamadı",
    });
  }

  // Shared timer ancak soft-delete DB'de doğrulandıktan sonra yayınlanır.
  if (existing.is_shared && existing.workspace_id) {
    io.to(`workspace-${existing.workspace_id}`).emit("timer-event", {
      event: "deleted",
      data: { id },
    });

    console.log(
      `[Socket] workspace-${existing.workspace_id} → deleted yayınlandı (DB onaylı)`,
    );
  }

  res.json({
    success: true,
    timer: updated,
  });
});

// Workspace'deki ortak timer'ları getir
app.get("/timers/shared", authenticate, async (req, res) => {
  if (!req.user.workspace_id) {
    return res.json({ timers: [] });
  }

  const { data, error } = await supabase
    .from("timers")
    .select("*, users!created_by(username)")
    .eq("workspace_id", req.user.workspace_id)
    .eq("is_shared", true)
    .eq("record_status", "active")
    .order("created_at", { ascending: false });

  if (error) {
    console.error("[/timers/shared] Supabase hatası:", error);
    return res.status(500).json({ error: "Timer'lar alınamadı" });
  }
  res.json({ timers: data });
});

// ─── Timer Routes ─────────────────────────────────────────────────────────

// Timer başlat - Telegram bildirimi planla
app.post("/timer/start", authenticate, async (req, res) => {
  const { timerId, timerName, endsAt } = req.body;

  if (!timerId || !timerName || !endsAt) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  const endTime = Number(endsAt);

  if (!Number.isFinite(endTime)) {
    return res.status(400).json({ error: "Geçersiz endsAt" });
  }

  // Timer'ı DB'den bul.
  const { data: existing, error: timerError } = await supabase
    .from("timers")
    .select("id, user_id, workspace_id, is_shared, record_status")
    .eq("id", timerId)
    .eq("record_status", "active")
    .single();

  if (timerError || !existing) {
    if (timerError?.code !== "PGRST116") {
      console.error("[POST /timer/start] Timer okuma hatası:", timerError);

      return res.status(500).json({
        error: "Timer okunamadı",
      });
    }

    return res.status(404).json({
      error: "Timer bulunamadı",
    });
  }

  // Timer kontrolündeki yetki kuralıyla aynı:
  // - Superadmin her yerde
  // - Shared timer: aynı workspace
  // - Personal timer: yalnız sahibi
  let canStart = false;

  if (req.user.role === "superadmin") {
    canStart = true;
  } else if (existing.is_shared) {
    canStart =
      Boolean(existing.workspace_id) &&
      existing.workspace_id === req.user.workspace_id;
  } else {
    canStart = existing.user_id === req.user.id;
  }

  if (!canStart) {
    return res.status(403).json({
      error: "Bu timer için bildirim planlama yetkiniz yok",
    });
  }

  scheduleTimer(
    req.user.id,
    timerId,
    timerName,
    endTime,
    async (_uid, tid, name) => {
      // Bildirim zamanı geldiğinde timer'ın GÜNCEL halini tekrar oku.
      const { data: timer, error } = await supabase
        .from("timers")
        .select("user_id, is_pay, is_shared, workspace_id, record_status")
        .eq("id", tid)
        .single();

      // Timer artık yoksa/silinmişse bildirim gönderme.
      if (error || !timer || timer.record_status !== "active") {
        return;
      }

      const paid = timer.is_pay ? "ODENDI" : "ODENMEDI";

      const messageText = `${name} bitti! ${paid}`;

      // Shared timer:
      // Telegram bağlı tüm workspace üyelerine gönder.
      if (timer.is_shared && timer.workspace_id) {
        const { data: members, error: membersError } = await supabase
          .from("users")
          .select("telegram_chat_id")
          .eq("workspace_id", timer.workspace_id)
          .not("telegram_chat_id", "is", null);

        if (membersError) {
          console.error(
            "[POST /timer/start] Workspace Telegram kullanıcıları okunamadı:",
            membersError,
          );
          return;
        }

        if (members?.length) {
          await Promise.all(
            members.map((member) =>
              sendTelegramMessage(member.telegram_chat_id, messageText),
            ),
          );
        }

        return;
      }

      // Personal timer:
      // Yalnız timer sahibine Telegram gönder.
      const { data: owner, error: ownerError } = await supabase
        .from("users")
        .select("telegram_chat_id")
        .eq("id", timer.user_id)
        .single();

      if (ownerError) {
        console.error(
          "[POST /timer/start] Timer sahibi okunamadı:",
          ownerError,
        );
        return;
      }

      // Telegram bağlı değilse bu tamamen normal.
      if (!owner?.telegram_chat_id) {
        return;
      }

      await sendTelegramMessage(owner.telegram_chat_id, messageText);
    },
  );

  // Telegram bağlı olmasa bile HTTP isteği düzgün kapanır.
  res.json({
    success: true,
    scheduled: true,
  });
});

// Timer iptal
app.post("/timer/cancel", authenticate, (req, res) => {
  const { timerId } = req.body;

  if (!timerId) {
    return res.status(400).json({ error: "timerId zorunlu" });
  }

  cancelTimer(timerId);
  res.json({ success: true });
});

// telegram bağlantısını kaldır/chatID'yi sil
app.patch("/telegram/cancel", authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;
    const { error } = await supabase
      .from("users")
      .update({ telegram_chat_id: null })
      .eq("id", user_id);
    if (error) {
      return res.status(500).json({ error: "telegram bağlantısı kesilemedi." });
    }
    return res.status(200).json({ success: "telegram bağlantısı kesildi." });
  } catch (err) {
    console.log(err);
  }
});

// telegram chatID çekme
app.post("/telegram/control", authenticate, async (req, res) => {
  try {
    const { user_id } = req.body;

    const { data, error } = await supabase
      .from("users")
      .select("telegram_chat_id")
      .eq("id", user_id)
      .single();

    if (error) {
      console.log("telegram control hatası:", error);
      return res.status(500).json({ success: false });
    }

    return res.json({
      success: true,
      connected: !!data.telegram_chat_id,
    });
  } catch (err) {
    console.log("telegram get işlemi hatası:", err);
    return res.status(500).json({ success: false });
  }
});

// ─── Sağlık kontrolü ──────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;

  // Geçiş dönemi:
  // Eski APK'lar henüz token göndermiyor.
  // Şimdilik bağlantıyı engellemiyoruz.
  if (!token) {
    const error = new Error("unauthorized");

    error.data = {
      status: 401,
      message: "Token gerekli",
    };

    return next(error);
  }

  const result = await validateAccessToken(token);

  if (!result.ok) {
    const error = new Error("unauthorized");

    error.data = {
      status: result.status,
      message: result.error,
    };

    return next(error);
  }

  socket.data.authenticated = true;
  socket.data.user = result.user;
  socket.data.sessionId = result.sessionId;

  next();
});

// ─── Socket.io — Ortak Ekran ──────────────────────────────────────────────

io.on("connection", (socket) => {
  const user = socket.data.user;
  const sessionId = socket.data.sessionId;

  // Kullanıcıya özel oda.
  // İleride force-logout / session yönetiminde işimize yarayacak.
  socket.join(`user-${user.id}`);

  // Bu login session'ına özel oda.
  socket.join(`session-${sessionId}`);

  // Workspace'i client seçmez.
  // DB'den doğrulanmış kullanıcı kaydı belirler.
  if (user.workspace_id) {
    socket.join(`workspace-${user.workspace_id}`);
  }

  console.log(
    "[Socket] Authenticated connection:",
    socket.id,
    "user:",
    user.username,
    "workspace:",
    user.workspace_id ?? null,
  );

  console.log(
    "[Socket] Bağlandı:",
    socket.id,
    "zaman:",
    new Date().toISOString(),
  );

  socket.on("disconnect", (reason) => {
    console.log(
      "[Socket] Ayrıldı:",
      socket.id,
      "sebep:",
      reason,
      "zaman:",
      new Date().toISOString(),
    );
  });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`[Server] ${PORT} portunda çalışıyor (HTTP + WebSocket)`);
});
