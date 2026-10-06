function daysBefore(date, days) {
  const value = new Date(`${date}T00:00:00Z`);
  value.setUTCDate(value.getUTCDate() - days);
  return value.toISOString().slice(0, 10);
}

// Each pass has its own successful-refresh date. A failed answers pass must not
// advance its watermark just because the priority questions pass succeeded.
export function createRefreshPlan({ mode, today, windowStart, houses, previous = {},
  hasExisting = true, forceFull = false, recentDays = 7, answerDays = 60 }) {
  if (!["all", "recent", "answers"].includes(mode)) throw new Error(`Invalid refresh mode: ${mode}`);
  for (const days of [recentDays, answerDays]) {
    if (!Number.isInteger(days) || days < 1) throw new Error("Lookback days must be positive integers");
  }
  const since = (days, lastSuccess) => {
    const overlap = daysBefore(today, days);
    const from = lastSuccess ? [overlap, daysBefore(lastSuccess, 1)].sort()[0] : overlap;
    return [windowStart, from].sort().at(-1);
  };
  const refresh = { ...previous.refresh };
  // Legacy datasets cover Commons only. A recent Lords fetch does not mean its
  // historical window has been backfilled.
  let completedHouses = previous.source?.completedHouses || (hasExisting ? ["Commons"] : []);
  const requests = [];
  if (forceFull || !hasExisting) {
    requests.push({ from: windowStart, to: today, dateField: "tabledWhen", houses });
    completedHouses = [...houses];
    refresh.recentAt = today;
    refresh.answersAt = today;
  } else {
    if (mode !== "answers") {
      requests.push({ from: since(recentDays, refresh.recentAt), to: today, dateField: "tabledWhen", houses });
      refresh.recentAt = today;
    }
    if (mode !== "recent") {
      // No tabled-date restriction: include answers to questions of any age.
      requests.push({ from: since(answerDays, refresh.answersAt), to: today, dateField: "answeredWhen", houses });
      const missingHouses = houses.filter(house => !completedHouses.includes(house));
      if (missingHouses.length) {
        requests.push({ from: windowStart, to: today, dateField: "tabledWhen", houses: missingHouses });
      }
      completedHouses = [...houses];
      refresh.answersAt = today;
    }
  }
  return { requests, refresh, completedHouses, replace: forceFull || !hasExisting };
}
