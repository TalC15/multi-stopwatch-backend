import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { scheduleTimer, cancelTimer } from "./timers.js";
import { sendTelegramMessage } from "./telegram.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Kullanıcı kaydı: { userId → chatId }
const users = new Map();

// Kullanıcı Telegram chat ID'sini kaydeder
app.post("/register", (req, res) => {
  const { userId, chatId } = req.body;

  if (!userId || !chatId) {
    return res.status(400).json({ error: "userId ve chatId zorunlu" });
  }

  users.set(userId, chatId);
  console.log(`[Register] ${userId} → ${chatId}`);
  res.json({ success: true });
});

// Timer başlatma
app.post("/timer/start", (req, res) => {
  const { userId, timerId, timerName, timerIsPay, endsAt } = req.body;

  console.log("[DEBUG] timer/start:", { userId, timerId, timerName, endsAt });
  console.log("[DEBUG] Date.now():", Date.now());
  console.log("[DEBUG] delay:", endsAt - Date.now());
  console.log("[DEBUG] users:", [...users.entries()]);

  if (!userId || !timerId || !timerName || !endsAt) {
    return res.status(400).json({ error: "Eksik parametre" });
  }

  if (!users.has(userId)) {
    return res.status(404).json({ error: "Kullanıcı kayıtlı değil" });
  }

  scheduleTimer(
    userId,
    timerId,
    timerName,
    timerIsPay,
    endsAt,
    async (uid, tid, name, isPay) => {
      console.log("[DEBUG] onEnd tetiklendi:", uid, name);
      const chatId = users.get(uid);
      if (!chatId) return;

      const paid = isPay ? "ODENDI" : "ODENMEDI";
      await sendTelegramMessage(chatId, `${name} bitti! ${paid}`);
    },
  );

  res.json({ success: true });
});

// Timer iptal
app.post("/timer/cancel", (req, res) => {
  const { timerId } = req.body;

  if (!timerId) {
    return res.status(400).json({ error: "timerId zorunlu" });
  }

  cancelTimer(timerId);
  res.json({ success: true });
});

// Sağlık kontrolü
app.get("/health", (req, res) => {
  res.json({ status: "ok", users: users.size });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[Server] ${PORT} portunda çalışıyor`);
});
