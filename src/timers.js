const timers = new Map();

export function scheduleTimer(userId, timerId, timerName, endsAt, onEnd) {
  if (timers.has(timerId)) {
    clearTimeout(timers.get(timerId).timeout);
  }

  if (!Number.isFinite(endsAt)) { timers.delete(timerId); return; }
  const entry = { timeout: null, timerName };
  timers.set(timerId, entry);
  const wake = () => {
    if (timers.get(timerId) !== entry) return;
    const delay = endsAt - Date.now();
    // Node's timeout ceiling is ~24.8 days; a larger delay fires immediately.
    if (delay > 0) {
      entry.timeout = setTimeout(wake, Math.min(delay, 2147483647));
      return;
    }
    timers.delete(timerId);
    Promise.resolve().then(() => onEnd(userId, timerId, timerName))
      .catch(() => console.error('[Timer] Bildirim tamamlanamadı'));
  };
  wake();
}

export function cancelTimer(timerId) {
  if (timers.has(timerId)) {
    clearTimeout(timers.get(timerId).timeout);
    timers.delete(timerId);
    console.log(`[Timer] Iptal edildi: ${timerId}`);
  }
}
