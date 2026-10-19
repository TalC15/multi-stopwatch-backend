export async function sendTelegramMessage(chatId, text) {
  const url = "https://api.telegram.org/bot" + process.env.TELEGRAM_BOT_TOKEN + "/sendMessage";
  
  const params = new URLSearchParams({
    chat_id: chatId,
    text: text,
  });

  try {
    const response = await fetch(url + "?" + params.toString());
    const data = await response.json();

    if (!data.ok) {
      console.error("[Telegram] Mesaj gönderilemedi");
    } else {
      console.log("[Telegram] Mesaj gönderildi");
    }
  } catch {
    console.error("[Telegram] Gönderim sonucu doğrulanamadı");
  }
}