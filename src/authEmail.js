// Production adapter only. Tests inject a sender; no NODE_ENV/dev fallback.
export function createAuthEmail(env = process.env, fetchImpl = globalThis.fetch) {
  return {
    configured() {
      return env.AUTH_EMAIL_PROVIDER === 'resend' && typeof env.RESEND_API_KEY === 'string' &&
        env.RESEND_API_KEY.length > 15 && /^[^\r\n<>\s]+@[^\r\n<>\s]+\.[^\r\n<>\s]+$/.test(env.AUTH_EMAIL_FROM || '');
    },
    async send({ to, purpose, code, url, challengeId, generation }) {
      if (!this.configured()) throw new Error('AUTH_NOT_READY');
      const title = purpose === 'mfa' ? 'KeepTimer giriş doğrulama kodu' :
        purpose === 'activation' ? 'KeepTimer hesabınızı güvenle hazırlayın' : 'KeepTimer parola sıfırlama';
      const body = purpose === 'mfa'
        ? `Giriş doğrulama kodunuz: ${code}\nKod 10 dakika içinde geçersiz olur. Kodu kimseyle paylaşmayın.`
        : `${purpose === 'activation' ? 'İlk parolanızı belirlemek' : 'Parolanızı sıfırlamak'} için bağlantıyı açın:\n${url}\nBağlantı 30 dakika geçerlidir ve yalnız bir kez kullanılabilir.`;
      try {
        const response = await fetchImpl('https://api.resend.com/emails', {
          method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000),
          headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json',
            'Idempotency-Key': `keeptimer-auth-${challengeId}-${generation}` },
          body: JSON.stringify({ from: env.AUTH_EMAIL_FROM, to: [to], subject: title,
            text: `${body}\n\nBu işlemi siz başlatmadıysanız bu mesajı dikkate almayın.\nKeepTimer` }),
        });
        const data = response.ok ? await response.json() : null;
        if (!response.ok || typeof data?.id !== 'string' || !data.id) throw new Error();
        // Provider acceptance is NOT inbox delivery. Never return provider payload.
        return { accepted: true };
      } catch { throw new Error('AUTH_EMAIL_UNAVAILABLE'); }
    },
  };
}
