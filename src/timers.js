const timers = new Map();

export function scheduleTimer(userId, timerId, timerName, timerIsPay, endsAt, onEnd) {
  if (timers.has(timerId)) {
    clearTimeout(timers.get(timerId).timeout);
  }

  const delay = endsAt - Date.now();

  if (delay <= 0) {
    onEnd(userId, timerId, timerName, timerIsPay);
    return;
  }

  console.log(`[Timer] ${timerName} - ${Math.round(delay / 1000)}sn sonra bildirim`);

  const timeout = setTimeout(() => {
    timers.delete(timerId);
    onEnd(userId, timerId, timerName, timerIsPay);
  }, delay);

  timers.set(timerId, { timeout, timerName });
}

export function cancelTimer(timerId) {
  if (timers.has(timerId)) {
    clearTimeout(timers.get(timerId).timeout);
    timers.delete(timerId);
    console.log(`[Timer] Iptal edildi: ${timerId}`);
  }
}