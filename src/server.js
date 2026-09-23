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
app.post("/auth/logout", authenticate, async (req, res) => {
  const { error } = await supabase
    .from("sessions")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", req.sessionId);

  if (error) return res.status(500).json({ error: "Çıkış yapılamadı" });
  res.json({ success: true });
});

// ─── Kullanıcı Yönetimi (sadece superadmin ve manager) ───────────────────

// Kullanıcı oluştur
app.post(
  "/users/create",
  authenticate,
  authorize("superadmin", "manager"),
  async (req, res) => {
    const { username, pin, role, workspace_id } = req.body;
    if(username.length>25 || pin.length>25) return res.status(400).json({error:"çok uzun isim veya PIN"})
    if (!username || !pin || !role) {
      return res.status(400).json({ error: "Eksik parametre" });
    }

    const usernameController = await supabase
    .from("users")
    .select("username")
    .eq("username",username)
    .single()

    if(usernameController.data) return res.status(400).json({error:"Bu isim zaten mevcut"})

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

    if (error) return res.status(500).json({ error: "Oturum kapatılamadı" });
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

  if (error) return res.status(500).json({ error: "Timer oluşturulamadı" });
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

  // Önce timer'ı bul. Yetki kontrolü yapılmadan hiçbir değişiklik yapma.
  const { data: existing, error: fetchError } = await supabase
    .from("timers")
    .select("id, user_id, workspace_id, is_shared, record_status")
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

  // Yetki kuralları:
  // - Superadmin tüm timer'ları güncelleyebilir.
  // - Shared timer'ı yalnız aynı workspace'teki kullanıcılar güncelleyebilir.
  // - Personal timer'ı yalnız sahibi güncelleyebilir.
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

  // started_at ilk kez running olduğunda kaydedilsin.
  // Bu RPC artık yalnızca yetki kontrolünden SONRA çalışıyor.
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
    .select("id")
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

  res.json({ success: true });
});

// Timer sil (gerçekten silmez, record_status = deleted yapar)
app.delete("/timers/:id", authenticate, async (req, res) => {
  const { id } = req.params;

  const { data: existing, error: fetchError } = await supabase
    .from("timers")
    .select("user_id, is_shared, workspace_id, record_status")
    .eq("id", id)
    .single();

  if (fetchError || !existing) {
    return res.status(404).json({ error: "Timer bulunamadı" });
  }

  const canDelete = existing.is_shared
    ? existing.workspace_id === req.user.workspace_id
    : existing.user_id === req.user.id;

  if (!canDelete) {
    return res.status(403).json({
      error: "Bu timer'ı silme yetkiniz yok",
    });
  }

  const { data: updated, error: updateError } = await supabase
    .from("timers")
    .update({ record_status: "deleted" })
    .eq("id", id)
    .select("id, record_status")
    .single();

  if (updateError) {
    console.error("Timer update hatası:", updateError);
    return res.status(500).json({
      error: "Timer silinemedi",
      details: updateError.message,
    });
  }

  if (!updated || updated.record_status !== "deleted") {
    console.error("Timer güncellenmedi:", updated);
    return res.status(500).json({
      error: "Timer güncellemesi doğrulanamadı",
    });
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

// Timer başlat
app.post("/timer/start", authenticate, async (req, res) => {
  const { timerId, timerName, endsAt } = req.body;

  console.log(req.body);
  if (!timerId || !timerName || !endsAt) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  const { data: user } = await supabase
    .from("users")
    .select("telegram_chat_id, workspace_id")
    .eq("id", req.user.id)
    .single();

  if (!user?.telegram_chat_id) {
    return;
  }

  scheduleTimer(
    req.user.id,
    timerId,
    timerName,
    endsAt,
    async (uid, tid, name) => {
      const { data: timer } = await supabase
        .from("timers")
        .select("is_pay, workspace_id")
        .eq("id", tid)
        .single();

      const paid = timer?.is_pay ? "ODENDI" : "ODENMEDI";
      const messageText = `${name} bitti! ${paid}`;

      if (timer?.workspace_id) {
        const { data: members } = await supabase
          .from("users")
          .select("telegram_chat_id")
          .eq("workspace_id", timer.workspace_id)
          .not("telegram_chat_id", "is", null);

        if (members && members.length > 0) {
          await Promise.all(
            members.map((m) =>
              sendTelegramMessage(m.telegram_chat_id, messageText),
            ),
          );
        }
      } else {
        await sendTelegramMessage(user.telegram_chat_id, messageText);
      }
    },
  );

  res.json({ success: true });
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

// ─── Socket.io — Ortak Ekran ──────────────────────────────────────────────

io.on("connection", (socket) => {
  console.log("[Socket] Bağlandı:", socket.id, "zaman:", new Date().toISOString());

  socket.on("join-workspace", (workspaceId) => {
    if (!workspaceId) return;
    socket.join(`workspace-${workspaceId}`);
    console.log(
      `[Socket] ${socket.id} → workspace-${workspaceId} odasına katıldı, zaman:`,
      new Date().toISOString(),
    );
  });

  socket.on("timer-event", ({ workspaceId, event, data }) => {
    if (!workspaceId) return;
    socket.to(`workspace-${workspaceId}`).emit("timer-event", { event, data });
    console.log(
      `[Socket] workspace-${workspaceId} → ${event} yayınlandı, zaman:`,
      new Date().toISOString(),
    );
  });

  socket.on("disconnect", (reason) => {
    console.log("[Socket] Ayrıldı:", socket.id, "sebep:", reason, "zaman:", new Date().toISOString());
  });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`[Server] ${PORT} portunda çalışıyor (HTTP + WebSocket)`);
});
