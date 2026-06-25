import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { scheduleTimer, cancelTimer } from "./timers.js";
import { sendTelegramMessage } from "./telegram.js";
import { authenticate, authorize, createSuperAdminIfNotExists, hashPin, verifyPin, generateAccessToken, generateRefreshToken, verifyToken } from "./auth.js";
import supabase from "./db.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Superadmin ilk kurulumda oluştur
createSuperAdminIfNotExists();

// ─── Auth Routes ──────────────────────────────────────────────────────────

// Giriş
app.post("/auth/login", async (req, res) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: "Kullanıcı adı ve PIN gerekli" });
  }

  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .single();

  if (error || !user) {
    return res.status(401).json({ error: "Kullanıcı bulunamadı" });
  }

  const pinValid = await verifyPin(pin, user.pin_hash);
  if (!pinValid) {
    return res.status(401).json({ error: "PIN hatalı" });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

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
app.post("/auth/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token gerekli" });
  }

  const decoded = verifyToken(refreshToken);
  if (!decoded) {
    return res.status(401).json({ error: "Geçersiz refresh token" });
  }

  const accessToken = generateAccessToken({ id: decoded.id });
  res.json({ accessToken });
});

// ─── Kullanıcı Yönetimi (sadece superadmin ve manager) ───────────────────

// Kullanıcı oluştur
app.post("/users/create", authenticate, authorize("superadmin", "manager"), async (req, res) => {
  const { username, pin, role, workspace_id } = req.body;

  if (!username || !pin || !role) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  if (req.user.role === "manager" && role !== "worker") {
    return res.status(403).json({ error: "Manager sadece worker oluşturabilir" });
  }

  // Manager workspace'i yoksa worker oluşturamaz
  if (req.user.role === "manager" && !req.user.workspace_id) {
    return res.status(400).json({ error: "Önce bir workspace oluşturun" });
  }

  const assignedWorkspaceId = req.user.role === "superadmin"
    ? (workspace_id || null)
    : req.user.workspace_id; // Manager kendi workspace'ini atar

  const pin_hash = await hashPin(pin);

  const { data, error } = await supabase
    .from("users")
    .insert({ username, pin_hash, role, workspace_id: assignedWorkspaceId })
    .select()
    .single();

  if (error) return res.status(500).json({ error: "Kullanıcı oluşturulamadı" });

  res.json({ success: true, user: { id: data.id, username: data.username, role: data.role } });
});

// ─── Workspace Routes ─────────────────────────────────────────────────────

// Workspace oluştur
app.post("/workspace/create", authenticate, authorize("superadmin", "manager"), async (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Workspace adı gerekli" });
  }

  // Davet kodu üret
  const inviteCode = Math.random().toString(36).substring(2, 8).toUpperCase();

  const { data: workspace, error } = await supabase
    .from("workspaces")
    .insert({ name, owner_id: req.user.id, invite_code: inviteCode })
    .select()
    .single();

  if (error) return res.status(500).json({ error: "Workspace oluşturulamadı" });

  // Kullanıcıyı workspace'e bağla
  await supabase
    .from("users")
    .update({ workspace_id: workspace.id })
    .eq("id", req.user.id);

  res.json({ success: true, workspace });
});

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
    .select("id, name, invite_code, owner_id")
    .eq("id", req.user.workspace_id)
    .single();

  if (error) return res.status(500).json({ error: "Workspace alınamadı" });
  res.json({ workspace: data });
});

// ─── Telegram Routes ──────────────────────────────────────────────────────

// Telegram chat ID kaydet
app.post("/register", authenticate, async (req, res) => {
  const { chatId } = req.body;

  if (!chatId) {
    return res.status(400).json({ error: "chatId gerekli" });
  }

  // Telegram'a test mesajı at
  try {
    const testUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    const params = new URLSearchParams({
      chat_id: chatId,
      text: "KeepTime bildirimleri aktifleştirildi! ✓",
    });

    const telegramRes = await fetch(testUrl + "?" + params.toString());
    const telegramData = await telegramRes.json();

    if (!telegramData.ok) {
      return res.status(400).json({ error: "Geçersiz Chat ID" });
    }
  } catch {
    return res.status(500).json({ error: "Telegram doğrulaması başarısız" });
  }

  // Doğrulama başarılı — kaydet
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
app.get("/users", authenticate, authorize("superadmin", "manager"), async (req, res) => {
  // Superadmin tüm kullanıcıları görür, manager sadece kendi workspace'ini
  let query = supabase.from("users").select("id, username, role, created_at, workspace_id");

  if (req.user.role !== "superadmin") {
    if (!req.user.workspace_id) {
      return res.json({ users: [] });
    }
    query = query.eq("workspace_id", req.user.workspace_id);
  }

  const { data, error } = await query;

  if (error) return res.status(500).json({ error: "Kullanıcılar alınamadı" });
  res.json({ users: data });
});

// Kullanıcı sil
app.delete("/users/:id", authenticate, authorize("superadmin", "manager"), async (req, res) => {
  const { id } = req.params;

  // Kendini silemez
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
});

// Tüm kullanıcıları listele (sadece superadmin)
app.get("/admin/users", authenticate, authorize("superadmin"), async (req, res) => {
  const { data, error } = await supabase
    .from("users")
    .select("id, username, role, workspace_id, created_at");

  if (error) return res.status(500).json({ error: "Kullanıcılar alınamadı" });
  res.json({ users: data });
});

// Kullanıcı güncelle (sadece superadmin)
app.patch("/admin/users/:id", authenticate, authorize("superadmin"), async (req, res) => {
  const { id } = req.params;
  const { username, role, workspace_id } = req.body;

  const { error } = await supabase
    .from("users")
    .update({ username, role, workspace_id })
    .eq("id", id);

  if (error) return res.status(500).json({ error: "Kullanıcı güncellenemedi" });
  res.json({ success: true });
});

// Kullanıcı sil (sadece superadmin)
app.delete("/admin/users/:id", authenticate, authorize("superadmin"), async (req, res) => {
  const { id } = req.params;

  if (id === req.user.id) {
    return res.status(400).json({ error: "Kendinizi silemezsiniz" });
  }

  const { error } = await supabase
    .from("users")
    .delete()
    .eq("id", id);

  if (error) return res.status(500).json({ error: "Kullanıcı silinemedi" });
  res.json({ success: true });
});

// Tüm workspace'leri listele (sadece superadmin)
app.get("/admin/workspaces", authenticate, authorize("superadmin"), async (req, res) => {
  const { data, error } = await supabase
    .from("workspaces")
    .select("id, name, owner_id, created_at");

  if (error) return res.status(500).json({ error: "Workspace'ler alınamadı" });
  res.json({ workspaces: data });
});

// Workspace'den ayrıl
app.post("/workspace/leave", authenticate, async (req, res) => {
  if (!req.user.workspace_id) {
    return res.status(400).json({ error: "Zaten bir workspace'de değilsiniz" });
  }

  // Manager ise workspace'de başka manager var mı kontrol et
  if (req.user.role === "manager") {
    const { data: otherManagers } = await supabase
      .from("users")
      .select("id")
      .eq("workspace_id", req.user.workspace_id)
      .eq("role", "manager")
      .neq("id", req.user.id);

    if (!otherManagers || otherManagers.length === 0) {
      return res.status(400).json({ 
        error: "Workspace'de tek manager sizsiniz. Ayrılmadan önce başka bir manager atayın." 
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
app.post("/workspace/refresh-invite", authenticate, authorize("manager", "superadmin"), async (req, res) => {
  if (!req.user.workspace_id) {
    return res.status(400).json({ error: "Bir workspace'de değilsiniz" });
  }

  const newInviteCode = Math.random().toString(36).substring(2, 8).toUpperCase();

  const { error } = await supabase
    .from("workspaces")
    .update({ invite_code: newInviteCode })
    .eq("id", req.user.workspace_id);

  if (error) return res.status(500).json({ error: "Davet kodu yenilenemedi" });

  res.json({ success: true, invite_code: newInviteCode });
});

// Workspace detayı (superadmin)
app.get("/admin/workspaces/:id", authenticate, authorize("superadmin"), async (req, res) => {
  const { id } = req.params;

  const { data: workspace, error } = await supabase
    .from("workspaces")
    .select("id, name, invite_code, owner_id, created_at")
    .eq("id", id)
    .single();

  if (error || !workspace) return res.status(404).json({ error: "Workspace bulunamadı" });

  const { data: members } = await supabase
    .from("users")
    .select("id, username, role, created_at")
    .eq("workspace_id", id);

  res.json({ workspace, members: members || [] });
});

// ─── Timer Routes ─────────────────────────────────────────────────────────

// Timer başlat
app.post("/timer/start", authenticate, async (req, res) => {
  const { timerId, timerName, timerIsPay, endsAt } = req.body;

  if (!timerId || !timerName || !endsAt) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  const { data: user } = await supabase
    .from("users")
    .select("telegram_chat_id, workspace_id")
    .eq("id", req.user.id)
    .single();

  if (!user?.telegram_chat_id) {
    return res.status(400).json({ error: "Telegram kaydı yok" });
  }

  scheduleTimer(req.user.id, timerId, timerName, timerIsPay, endsAt, async (uid, tid, name, isPay) => {
    const paid = isPay ? "ODENDI" : "ODENMEDI";
    await sendTelegramMessage(user.telegram_chat_id, `${name} bitti! ${paid}`);
  });

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

// ─── Sağlık kontrolü ──────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[Server] ${PORT} portunda çalışıyor`);
});