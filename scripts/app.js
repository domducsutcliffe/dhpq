// ── Crypto gate ──────────────────────────────────────────────────────────────
// Data files are AES-256-GCM encrypted at build time. The password derives the key via
// PBKDF2. No password or hash is stored in this source — a wrong password simply fails
// to decrypt the data.
//
// The `.enc` is a binary container (see scripts/encrypt-data.mjs): "PQE1" magic +
// iterations + salt/iv/tag + ciphertext. It is fetched straight into an ArrayBuffer, so
// there is no base64 to decode — the previous base64 format cost ~9s of main-thread work
// on the big dataset turning 37MB of text into bytes, which was the whole "slow to
// decrypt" complaint (the actual AES + PBKDF2 is ~150ms).
const DEFAULT_PBKDF2_ITERATIONS = 100_000;

async function deriveKey(password, salt, iterations = DEFAULT_PBKDF2_ITERATIONS) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function decryptContainer(buffer, password) {
  const bytes = new Uint8Array(buffer);
  const magic = bytes.length >= 52 ? String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) : "";
  if (magic !== "PQE1" && magic !== "PQE2") {
    throw new Error("unrecognised data container");
  }
  const iterations = new DataView(buffer).getUint32(4, true);
  const salt = bytes.subarray(8, 24);
  const iv = bytes.subarray(24, 36);
  const tag = bytes.subarray(36, 52);
  const cipher = bytes.subarray(52);

  // AES-GCM expects ciphertext + authTag concatenated.
  const combined = new Uint8Array(cipher.length + tag.length);
  combined.set(cipher);
  combined.set(tag, cipher.length);

  const key = await deriveKey(password, salt, iterations);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);

  // PQE2 payloads are gzip-compressed — inflate natively (fast, off the base64 path).
  if (magic === "PQE2") {
    const stream = new Response(plainBuf).body.pipeThrough(new DecompressionStream("gzip"));
    const inflated = await new Response(stream).arrayBuffer();
    return new TextDecoder().decode(inflated);
  }
  return new TextDecoder().decode(plainBuf);
}

let _resolvePassword;
// Deliberately `let`, and re-armed after every failed attempt: a `const` promise resolves
// once and keeps handing back the FIRST password forever, so a single typo would lock you
// out of the dashboard until you reloaded the page, however many times you retyped it.
let passwordReady = new Promise((resolve) => { _resolvePassword = resolve; });

function awaitNextPassword() {
  passwordReady = new Promise((resolve) => { _resolvePassword = resolve; });
  return passwordReady;
}

// Build (once) the password overlay and wire its submit. The overlay is opaque and
// position:fixed, so it covers the dashboard on its own — but we ALSO hide `.page`, and
// crucially we do that only AFTER the overlay is safely in the DOM. The old order (hide
// page, then build overlay) meant any hiccup on a cold load left a hidden page with no
// prompt: a blank screen that only a reload fixed. This order cannot do that.
function buildAuthOverlay() {
  if (document.getElementById("auth-overlay")) return;
  const overlay = document.createElement("div");
  overlay.id = "auth-overlay";
  overlay.innerHTML = `
    <div style="position:fixed;inset:0;background:var(--page,#f6f6ef);z-index:9999;display:flex;align-items:center;justify-content:center;">
      <form id="auth-form" style="background:#fff;border:1px solid #d9d4bd;padding:24px 28px;max-width:300px;width:100%;font-family:'Inter',sans-serif;">
        <h2 style="margin:0 0 12px;font-size:14px;font-weight:700;">🔒 Dashboard Access</h2>
        <input id="auth-input" type="password" placeholder="Enter password" autofocus
          style="width:100%;min-height:32px;border:1px solid #d9d4bd;padding:6px 8px;font:inherit;margin-bottom:10px;border-radius:0;">
        <button type="submit" id="auth-btn"
          style="width:100%;min-height:32px;background:#ff6600;border:none;color:#fff;font:inherit;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:0.5px;font-size:12px;">
          Enter
        </button>
        <p id="auth-error" style="color:#bd2130;font-size:11px;margin:8px 0 0;display:none;">Incorrect password</p>
      </form>
    </div>`;
  document.body.appendChild(overlay);
  const page = document.querySelector(".page");
  if (page) page.style.display = "none";
  document.getElementById("auth-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const val = document.getElementById("auth-input").value;
    document.getElementById("auth-btn").textContent = "Decrypting…";
    document.getElementById("auth-error").style.display = "none";
    _resolvePassword(val);
  });
}

function initAuthGate() {
  try {
    const stored = sessionStorage.getItem("pq-auth-ok");
    if (stored) {
      _resolvePassword(stored);
      return;
    }
    buildAuthOverlay();
  } catch (err) {
    // Never strand the user on a blank page — if the gate fails to initialise, keep the
    // dashboard visible and try once more to raise the prompt.
    console.error("Auth gate init failed:", err);
    const page = document.querySelector(".page");
    if (page) page.style.display = "";
    try {
      buildAuthOverlay();
    } catch (err2) {
      console.error("Auth overlay build failed:", err2);
    }
  }
}

// Modules are deferred, so the DOM is normally ready here — but guard anyway, since the
// gate touching `document.body`/`.page` before they exist is exactly what blanks the page.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAuthGate, { once: true });
} else {
  initAuthGate();
}
// ─────────────────────────────────────────────────────────────────────────────

import { DEFAULT_VERTICAL_ID, getVertical } from "../config.js?v=commons-1";

const VERTICAL = getVertical(DEFAULT_VERTICAL_ID);

// Word-boundary, case-insensitive matcher for the vertical's topic roots. This build is
// department-wide (no match roots), so there is no client-side scope filter — but the
// hook stays, since re-pointing config.js at a single topic is the whole point of it.
const VERTICAL_MATCH = VERTICAL.matchRoots.length
  ? new RegExp(`\\b(${VERTICAL.matchRoots.join("|")})`, "i")
  : null;

// Party shown as a coloured square next to the member name (party column removed).
// Emoji squares are a limited palette, so a few minor parties share a colour — the
// full party name is always available on hover via the title attribute.
const PARTY_EMOJI = {
  Lab: "🟥",
  Con: "🟦",
  LD: "🟧",
  SNP: "🟨",
  Green: "🟩",
  DUP: "🟥",
  RUK: "🟦",
  Ind: "⬜",
  SDLP: "🟩",
  PC: "🟩",
  UUP: "🟦",
  Alba: "🟦",
  UKIP: "🟪",
  CUK: "⬛",
  RB: "⬜",
};

// The Parliament list endpoint caps question text at 255 chars, and a complete question
// always ends in sentence punctuation. Anything else is still awaiting repair from the
// detail endpoint (the refresh repairs a batch per run), so mark it with a "…" and a link
// to the full text rather than showing a sentence that just stops mid-clause.
function isTruncatedQuestion(text) {
  const trimmed = String(text || "").trim();
  return trimmed.length > 0 && !/[.?!]["')\]]*$/.test(trimmed);
}

// Progress readout for the full-text repair backlog. Parliament's list endpoint caps
// question text at 255 chars; the refresh repairs a capped batch per run (so it doesn't
// trip the API's bot protection), so this counts down over successive runs. Hidden once
// there's nothing left to repair.
function renderFullTextProgress() {
  const el = elements.fullTextProgress;
  if (!el) return;
  const total = state.questions.length;
  if (!total) {
    el.hidden = true;
    return;
  }
  const pending = state.questions.reduce(
    (n, q) => n + (isTruncatedQuestion(q.questionText) ? 1 : 0),
    0,
  );
  if (!pending) {
    el.hidden = true;
    return;
  }
  const done = total - pending;
  const pct = Math.floor((done / total) * 100);
  el.hidden = false;
  el.innerHTML = `
    <span class="ftp-label" title="Parliament's list API returns only the first 255 characters of a question. The daily refresh repairs a batch from the detail endpoint each run; these are the ones still to do — each shows a “… full question” link meanwhile.">
      Full question text: <strong>${formatNumber.format(done)}</strong> of ${formatNumber.format(total)} complete
      · <strong>${formatNumber.format(pending)}</strong> awaiting repair
    </span>
    <span class="ftp-bar"><span class="ftp-fill" style="width:${pct}%"></span></span>
    <span class="ftp-pct">${pct}%</span>
  `;
}

// Every PQ opens with the same formula. Short mode drops it so the question itself starts
// the line; the stored text is untouched, so search, the truncation test and the export
// still see the whole thing. (PQ_OPENER is the pattern the similar-questions panel strips.)
function displayQuestionText(question) {
  const text = String(question.questionText || "");
  if (!state.shortMode) return text;
  const trimmed = text.replace(PQ_OPENER, "");
  // Nothing matched — a question that doesn't open with the formula is left alone.
  if (trimmed === text) return text;
  // What follows the formula is mid-sentence ("what steps her Department…"), so it needs
  // a capital to read as the start of one.
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

function questionTextHtml(question) {
  const text = escapeHtml(displayQuestionText(question));
  if (!isTruncatedQuestion(question.questionText)) return text;
  return `${text}<a class="question-more" href="${escapeHtml(question.url)}" target="_blank" rel="noopener noreferrer" title="Parliament's API returns only the first 255 characters of this question — open the full text on parliament.uk">… full question ↗</a>`;
}

function partyEmoji(question) {
  const abbr = question.member.partyAbbreviation || question.member.party || "";
  return PARTY_EMOJI[abbr] || "⬜";
}

// The dataset covers exactly one window (config.js), so there are no Parliament-period
// filters here — those are only needed by a build that holds several Parliaments.
// The volume chart's bucket adapts to how wide that window is: a week of questions wants
// a point per day, a whole Parliament wants a point per month.
const state = {
  questions: [],
  summary: null,
  query: "",
  party: "",
  region: "",
  answer: "",
  searchQuestionOnly: true,
  chartPoints: [],
  bucketMode: "day", // "day" | "month" — recomputed from the loaded window
  selectedBucket: "",
  selectedTopic: "",
  // Drops the "To ask the Secretary of State…" pro forma from the front of each question
  // in the table. A display preference, not a filter, so Reset Filters leaves it alone.
  shortMode: false,
  // Set to a yyyy-mm-dd date to show only questions tabled that day. Driven by the
  // "Today" button, which uses the most recent tabling day present in the data —
  // not the calendar date, since Parliament doesn't table every day.
  tabledOn: "",
};

const DAY_BUCKET_MAX_SPAN = 60; // days; wider windows switch to monthly buckets

function resolveBucketMode() {
  const first = parseDate(state.summary?.dateRange?.oldestTabled);
  const last = parseDate(state.summary?.dateRange?.newestTabled);
  if (!first || !last) return "day";
  const spanDays = (last - first) / 86_400_000;
  return spanDays > DAY_BUCKET_MAX_SPAN ? "month" : "day";
}

// The chart/filter key for a question: its tabled date, or the month of it.
function bucketKey(dateTabled) {
  const date = String(dateTabled || "");
  return state.bucketMode === "month" ? date.slice(0, 7) : date;
}

function bucketLabel(key, long = false) {
  if (state.bucketMode === "month") {
    const date = parseDate(`${key}-01`);
    return date
      ? date.toLocaleDateString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" })
      : key;
  }
  const date = parseDate(key);
  if (!date) return key;
  return long
    ? date.toLocaleDateString("en-GB", {
        weekday: "long",
        day: "numeric",
        month: "long",
        timeZone: "UTC",
      })
    : shortDate(key);
}

const elements = {
  status: document.querySelector("#data-status"),
  total: document.querySelector("#metric-total"),
  answered: document.querySelector("#metric-answered"),
  latest: document.querySelector("#metric-latest"),
  partyMetric: document.querySelector("#metric-party"),
  regionMetric: document.querySelector("#metric-region"),
  search: document.querySelector("#search"),
  searchQuestionOnly: document.querySelector("#search-question-only"),
  shortMode: document.querySelector("#short-mode"),
  partyFilter: document.querySelector("#party-filter"),
  regionFilter: document.querySelector("#region-filter"),
  answerFilter: document.querySelector("#answer-filter"),
  monthlyRange: document.querySelector("#monthly-range"),
  monthlyChart: document.querySelector("#monthly-chart"),
  volumeTitle: document.querySelector("#volume-title"),
  partyChart: document.querySelector("#party-chart"),
  regionChart: document.querySelector("#region-chart"),
  themeChart: document.querySelector("#theme-chart"),
  resultsCount: document.querySelector("#results-count"),
  fullTextProgress: document.querySelector("#fulltext-progress"),
  todayFilter: document.querySelector("#today-filter"),
  exportButton: document.querySelector("#export-xlsx"),
  table: document.querySelector("#question-table"),
  footer: document.querySelector("#data-footer"),
  tooltip: document.querySelector("#chart-tooltip"),
  answerTooltip: document.querySelector("#answer-tooltip"),
  resetFilters: document.querySelector("#reset-filters"),
  similarPanel: document.querySelector("#similar-panel"),
};

// Full answer text for the hover tooltip, keyed by question id (populated per render).
const answerByQid = new Map();
// The same, for the rows in the similar-questions panel. Kept separate because
// renderTable clears its map on every render, and the panel outlives a render.
const similarAnswerByQid = new Map();

const formatNumber = new Intl.NumberFormat("en-GB");
const formatDate = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
});

function parseDate(value) {
  if (!value) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function shortDate(value) {
  const date = parseDate(value);
  return date ? formatDate.format(date) : "-";
}

function formatGeneratedAt(isoString) {
  if (!isoString) return "-";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "-";
  const day = date.getDate();
  const months = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  ];
  const monthName = months[date.getMonth()];
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${day} ${monthName} @ ${hours}:${minutes}`;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function getQuestionTopic(question) {
  return question.topic || "General";
}

function getTopicCounts(questions) {
  const counts = {};
  for (const q of questions) {
    const topic = getQuestionTopic(q);
    counts[topic] = (counts[topic] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function countBy(items, getKey) {
  const counts = new Map();
  for (const item of items) {
    const key = getKey(item) || "Unknown";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

// Is the view narrowed at all? (Answer state is a filter too, but "answered" vs the whole
// postbag is a different question from "how much of the postbag is about one topic", and
// the share reads oddly against it — so every narrowing counts here.)
function isFiltered() {
  return Boolean(
    state.query.trim() ||
      state.party ||
      state.region ||
      state.answer ||
      state.selectedTopic ||
      state.selectedBucket ||
      state.tabledOn,
  );
}

// The most recent day on which questions were actually tabled. Parliament doesn't table
// every day (recess, weekends), so "today" here means the newest tabling day in the data
// rather than the calendar date — otherwise the button would usually show nothing.
function latestTabledDate() {
  return (
    state.summary?.dateRange?.newestTabled ||
    state.questions.reduce((max, q) => (q.dateTabled > max ? q.dateTabled : max), "")
  );
}

function renderTodayButton() {
  const btn = elements.todayFilter;
  if (!btn) return;
  const latest = latestTabledDate();
  if (!latest) {
    btn.hidden = true;
    return;
  }
  const active = state.tabledOn === latest;
  btn.hidden = false;
  btn.textContent = `⚡ Today · ${shortDate(latest)}`;
  btn.classList.toggle("active", active);
  btn.title = active
    ? "Showing only questions tabled on the most recent tabling day — click to clear"
    : `Show only the questions tabled on ${shortDate(latest)}, the most recent day Parliament tabled questions`;
  btn.setAttribute("aria-pressed", String(active));
}

// A share of the whole dataset. Small subjects are the norm across a whole department
// (the biggest is ~6%), so keep enough precision for a fraction of a percent to still
// say something rather than collapsing to "0%".
function formatShare(count, total) {
  if (!total) return "0%";
  const pct = (count / total) * 100;
  if (pct === 0) return "0%";
  if (pct < 0.1) return `${pct.toFixed(2)}%`;
  if (pct < 10) return `${pct.toFixed(1)}%`;
  return `${Math.round(pct)}%`;
}

function questionText(question) {
  return [
    question.uin,
    question.heading,
    question.questionText,
    question.answerText,
    question.member?.name,
    question.member?.party,
    question.member?.partyAbbreviation,
    question.member?.constituency,
    question.region?.nhsRegion,
    question.region?.nation,
  ]
    .join(" ")
    .toLowerCase();
}

function getScopedQuestions() {
  // The refresh script already pruned the dataset to the rolling window, so "in scope"
  // here means only the vertical's keyword filter — and a department-wide build has none.
  if (!VERTICAL_MATCH) return state.questions;
  return state.questions.filter(
    (question) =>
      VERTICAL_MATCH.test(question.heading || "") || VERTICAL_MATCH.test(question.questionText || ""),
  );
}

// Build the search matchers for a query. Each term must match a WHOLE word — so a
// two-word search like "Ben Maguire" can't sneak in via "benefit" (matching "ben") plus a
// "Maguire" somewhere else — except the LAST term, which matches as a prefix so
// search-as-you-type ("dent" → "dental") still works.
function buildQueryMatchers(query) {
  const words = query.split(/\s+/).filter(Boolean);
  return words.map((word, i) => {
    const esc = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return i === words.length - 1 ? new RegExp(`\\b${esc}`) : new RegExp(`\\b${esc}\\b`);
  });
}

function getFilteredQuestions(excludeBucket = false, excludeTopic = false, excludeParty = false, excludeRegion = false) {
  const query = state.query.trim().toLowerCase();
  const exactUin = query.match(/^(?:uin:?\s*)?(\d{2,})$/)?.[1] || "";
  const queryMatchers = query ? buildQueryMatchers(query) : [];

  return getScopedQuestions().filter((question) => {
    if (!excludeParty && state.party) {
      const party = question.member.partyAbbreviation || question.member.party || "Unknown";
      if (party !== state.party) return false;
    }

    if (!excludeRegion && state.region && question.region.nhsRegion !== state.region) return false;
    if (state.answer === "answered" && !question.answered) return false;
    if (state.answer === "unanswered" && question.answered) return false;

    if (exactUin) {
      return String(question.uin || "") === exactUin;
    }

    if (query) {
      // Member name and constituency are always searchable (they're metadata, not
      // question/answer text), so "Search question text only" still lets you find a
      // member by name — and clicking a name/constituency in the table just fills the
      // search with it.
      const questionFields = [
        question.heading,
        question.questionText,
        question.member?.name,
        question.member?.constituency,
      ];
      const fields = state.searchQuestionOnly
        ? questionFields
        : [...questionFields, question.answerText];
      const textToSearch = fields.filter(Boolean).join(" ").toLowerCase();
      if (!queryMatchers.every((re) => re.test(textToSearch))) return false;
    }

    if (!excludeBucket && state.selectedBucket) {
      if (bucketKey(question.dateTabled) !== state.selectedBucket) return false;
    }

    if (state.tabledOn && question.dateTabled !== state.tabledOn) return false;

    if (!excludeTopic && state.selectedTopic) {
      if (getQuestionTopic(question) !== state.selectedTopic) return false;
    }

    return true;
  });
}

function renderMetrics(items) {
  const partyCounts = countBy(items, (question) => question.member.partyAbbreviation || question.member.party);
  const regionCounts = countBy(items, (question) => question.region.nhsRegion);
  const answered = items.filter((question) => question.answered).length;
  const newest = items.map((question) => question.dateTabled).filter(Boolean).sort().at(-1);

  elements.total.textContent = formatNumber.format(items.length);
  elements.answered.textContent = `${formatNumber.format(answered)} / ${formatNumber.format(items.length - answered)}`;
  elements.latest.textContent = shortDate(newest);
  elements.partyMetric.textContent = partyCounts[0]
    ? `${partyCounts[0].key} (${formatNumber.format(partyCounts[0].count)})`
    : "-";
  elements.regionMetric.textContent = regionCounts[0]
    ? `${regionCounts[0].key} (${formatNumber.format(regionCounts[0].count)})`
    : "-";
}

function renderScopeStatus(filteredCount) {
  if (!state.summary) return;
  const refreshed = formatGeneratedAt(state.summary.generatedAt);
  // A rolling window is best described by its length ("the last 7 days"); an absolute one
  // by where it starts ("since 9 Jul 2024" — the start of this Parliament).
  const lookbackDays = state.summary.window?.lookbackDays;
  const windowPhrase = lookbackDays
    ? `tabled in the last ${lookbackDays} days`
    : `tabled since ${shortDate(state.summary.window?.startsOn || state.summary.dateRange.oldestTabled)}`;

  const filterParts = [];
  if (state.selectedTopic) {
    filterParts.push(`topic "${escapeHtml(state.selectedTopic)}"`);
  }
  if (state.party) {
    filterParts.push(`party "${escapeHtml(state.party)}"`);
  }
  if (state.region) {
    filterParts.push(`NHS region "${escapeHtml(state.region)}"`);
  }
  if (state.selectedBucket) {
    filterParts.push(`${state.bucketMode} "${escapeHtml(bucketLabel(state.selectedBucket))}"`);
  }

  const totalCount = state.summary.totals.questions;
  const total = formatNumber.format(totalCount);
  const shown = formatNumber.format(filteredCount);
  // With no keyword scope, the interesting number about any filter — a subject, a party,
  // a search — is how much of the department's whole postbag it accounts for.
  // Kept deliberately short so the top bar has room for the controls. The scope
  // ("every subject, tabled since …") and the refresh time now live in the footer.
  let statusText = isFiltered()
    ? `${shown} of ${total} PQs (${formatShare(filteredCount, totalCount)})`
    : `${total} PQs`;

  if (filterParts.length > 0) {
    statusText += ` <span style="cursor:pointer; text-decoration:underline; font-weight:bold; margin-left:6px; color:#000000;" id="clear-filters-link">(clear filters)</span>`;
  }

  elements.status.innerHTML = statusText;

  let footerText = `Every ${VERTICAL.house} written question in scope, tabled between ${shortDate(
    state.summary.dateRange.oldestTabled,
  )} and ${shortDate(state.summary.dateRange.newestTabled)} — no keyword filter.`;
  const unheaded = state.summary.totals.unheaded || 0;
  if (unheaded) {
    footerText += ` Parliament assigns subject headings a few days after tabling, so ${formatNumber.format(
      unheaded,
    )} of the newest questions sit under "Awaiting heading" until it publishes theirs; their text is still fully searchable.`;
  }
  if (state.selectedBucket) {
    footerText += ` Filtered to ${bucketLabel(state.selectedBucket, true)}.`;
  }
  if (state.selectedTopic) {
    footerText += ` Filtered to show only questions under topic "${state.selectedTopic}".`;
  }
  if (state.party) {
    footerText += ` Filtered to show only questions from party "${state.party}".`;
  }
  if (state.region) {
    footerText += ` Filtered to show only questions from NHS region "${state.region}".`;
  }
  // The top bar is now just a count, so the scope and refresh time live down here.
  footerText += ` Refreshed ${refreshed}.`;
  // Said plainly, on every page view: this is a personal tool over Parliament's open
  // data, not a departmental product, and nobody should read it as one.
  footerText += " Unofficial personal project built on the UK Parliament Written Questions API — not affiliated with, endorsed by, or produced by any government department.";
  elements.footer.textContent = footerText;
  renderFullTextProgress();
  renderTodayButton();

  const clearBothBtn = document.querySelector("#clear-filters-link");
  if (clearBothBtn) {
    clearBothBtn.addEventListener("click", () => {
      state.selectedBucket = "";
      state.selectedTopic = "";
      state.tabledOn = "";
      state.party = "";
      state.region = "";
      elements.partyFilter.value = "";
      elements.regionFilter.value = "";
      render();
    });
  }
}

function renderSelects() {
  const scoped = getScopedQuestions();
  const parties = countBy(scoped, (question) => question.member.partyAbbreviation || question.member.party);
  const regions = countBy(scoped, (question) => question.region.nhsRegion);

  const partyStillPresent = !state.party || parties.some((party) => party.key === state.party);
  const regionStillPresent = !state.region || regions.some((region) => region.key === state.region);
  if (!partyStillPresent) state.party = "";
  if (!regionStillPresent) state.region = "";

  elements.partyFilter.innerHTML =
    '<option value="">All parties</option>' +
    parties.map((party) => `<option value="${escapeHtml(party.key)}">${escapeHtml(party.key)}</option>`).join("");
  elements.regionFilter.innerHTML =
    '<option value="">All NHS regions</option>' +
    regions.map((region) => `<option value="${escapeHtml(region.key)}">${escapeHtml(region.key)}</option>`).join("");
  elements.partyFilter.value = state.party;
  elements.regionFilter.value = state.region;
}

// A smoothed spline. A Catmull-Rom-ish curve overshoots on sharp
// drops (on the 7-day view it dived below the axis across the quiet weekend, drawing
// negative questions), so the curve is drawn inside a clip path fixed to the plot area —
// it keeps the smoothing without ever painting below zero.
const getLineProps = (pointA, pointB) => {
  const lengthX = pointB.x - pointA.x;
  const lengthY = pointB.y - pointA.y;
  return {
    length: Math.sqrt(lengthX * lengthX + lengthY * lengthY),
    angle: Math.atan2(lengthY, lengthX),
  };
};

const getControlPoint = (current, previous, next, reverse) => {
  const p = previous || current;
  const n = next || current;
  const smoothing = 0.15;
  const o = getLineProps(p, n);
  const angle = o.angle + (reverse ? Math.PI : 0);
  const length = o.length * smoothing;
  const x = current.x + Math.cos(angle) * length;
  const y = current.y + Math.sin(angle) * length;
  return [x, y];
};

const getBezierPath = (points) => {
  return points.reduce((acc, point, i, a) => {
    if (i === 0) {
      return `M ${point.x.toFixed(1)} ${point.y.toFixed(1)}`;
    }
    const [cpsX, cpsY] = getControlPoint(a[i - 1], a[i - 2], point, false);
    const [cpeX, cpeY] = getControlPoint(point, a[i - 1], a[i + 1], true);
    return `${acc} C ${cpsX.toFixed(1)} ${cpsY.toFixed(1)}, ${cpeX.toFixed(1)} ${cpeY.toFixed(1)}, ${point.x.toFixed(1)} ${point.y.toFixed(1)}`;
  }, "");
};

// Every bucket in the window gets a point, including empty ones (weekends, recess) —
// otherwise the line silently closes the gap and a quiet Sunday looks like a busy one.
function everyBucketBetween(first, last) {
  const buckets = [];
  const cursor = parseDate(state.bucketMode === "month" ? `${first.slice(0, 7)}-01` : first);
  const end = parseDate(last);
  if (!cursor || !end) return buckets;
  while (cursor <= end) {
    buckets.push(bucketKey(cursor.toISOString().slice(0, 10)));
    if (state.bucketMode === "month") {
      cursor.setUTCMonth(cursor.getUTCMonth() + 1);
    } else {
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
  }
  return buckets;
}

function renderLineChart(items) {
  const byBucket = new Map();
  for (const question of items) {
    if (!question.dateTabled) continue;
    const key = bucketKey(question.dateTabled);
    if (!byBucket.has(key)) byBucket.set(key, []);
    byBucket.get(key).push(question);
  }

  // Span the full stored window, not just the buckets the current filter happens to hit,
  // so the x-axis doesn't rescale every time you click a party.
  const oldest = state.summary?.dateRange?.oldestTabled;
  const newest = state.summary?.dateRange?.newestTabled;
  const spanned = oldest && newest ? everyBucketBetween(oldest, newest) : [];
  const buckets = spanned.length ? spanned : [...byBucket.keys()].sort();

  if (!buckets.length) {
    state.chartPoints = [];
    elements.monthlyChart.innerHTML = '<p class="chart-note">No matching data.</p>';
    elements.monthlyRange.textContent = "";
    return;
  }

  const containerWidth = elements.monthlyChart ? elements.monthlyChart.clientWidth : 0;
  const width = containerWidth > 16 ? (containerWidth - 16) : 760;
  const height = 220;
  const pad = 28;
  const max = Math.max(...buckets.map((key) => (byBucket.get(key) || []).length), 1);
  const step = buckets.length > 1 ? (width - pad * 2) / (buckets.length - 1) : 0;
  const points = buckets.map((key, index) => {
    const bucketQuestions = byBucket.get(key) || [];
    const count = bucketQuestions.length;
    const x = pad + index * step;
    const y = height - pad - (count / max) * (height - pad * 2);
    const themeCounts = getTopicCounts(bucketQuestions).filter((t) => t.count > 0).slice(0, 5);
    return { key, count, x, y, themeCounts };
  });
  state.chartPoints = points;

  const path = getBezierPath(points);
  const area = points.length > 1
    ? `${path} L ${points.at(-1).x.toFixed(1)} ${height - pad} L ${points[0].x.toFixed(1)} ${height - pad} Z`
    : "";

  const dotR = points.length > 40 ? 2.5 : points.length > 20 ? 3 : 4;
  const dotRActive = dotR + 2;

  // Label the points — "Tue / 8", or "Jul / 2024" with the year only where it changes —
  // but only as many as fit the width. A Parliament is ~25 months, which is fine on a wide
  // screen but overlaps into an unreadable smear on a phone, so thin to every Nth label
  // based on how much room each one has (~46px). Desktop keeps every label; narrow screens
  // drop to a readable handful.
  const maxLabels = Math.max(4, Math.floor(width / 46));
  const stride = Math.max(1, Math.ceil(points.length / maxLabels));
  let lastYear = "";
  const ticks = points.map((point, index) => {
    const show = index % stride === 0 || index === points.length - 1;
    if (!show) return { x: point.x, label: "", sub: "" };
    if (state.bucketMode === "month") {
      const [year, month] = point.key.split("-");
      const date = parseDate(`${point.key}-01`);
      const showYear = year !== lastYear ? year : "";
      lastYear = year;
      return {
        x: point.x,
        label: date ? date.toLocaleDateString("en-GB", { month: "short", timeZone: "UTC" }) : month,
        sub: showYear,
      };
    }
    const date = parseDate(point.key);
    return {
      x: point.x,
      label: date ? date.toLocaleDateString("en-GB", { weekday: "short", timeZone: "UTC" }) : "",
      sub: date ? String(date.getUTCDate()) : "",
    };
  });

  if (elements.volumeTitle) {
    elements.volumeTitle.textContent = state.bucketMode === "month" ? "Monthly volume" : "Daily volume";
  }
  elements.monthlyRange.textContent = `${shortDate(oldest)} to ${shortDate(newest)}`;
  elements.monthlyChart.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${state.bucketMode === "month" ? "Monthly" : "Daily"} ${VERTICAL.topic} PQ volume" style="--dot-r: ${dotR}px; --dot-r-active: ${dotRActive}px;">
      <defs>
        <clipPath id="plot-clip">
          <rect x="0" y="0" width="${width}" height="${height - pad}"></rect>
        </clipPath>
      </defs>
      <line class="axis" x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}"></line>
      <line class="axis" x1="${pad}" y1="${pad}" x2="${pad}" y2="${height - pad}"></line>
      <g clip-path="url(#plot-clip)">
        ${area ? `<path class="trend-area" d="${area}"></path>` : ""}
        ${path ? `<path class="trend-line" d="${path}"></path>` : ""}
      </g>
      ${points
        .map((point, index) => {
          const isActive = point.key === state.selectedBucket;
          return `
              <circle class="data-point${isActive ? " active" : ""}" cx="${point.x.toFixed(1)}" cy="${point.y.toFixed(1)}" data-index="${index}"></circle>
            `;
        })
        .join("")}
      ${ticks
        .map(
          (tick) => `
            <text x="${tick.x}" y="${height - 15}" text-anchor="middle" font-size="9" fill="#777">${tick.label}</text>
            ${tick.sub ? `<text x="${tick.x}" y="${height - 3}" text-anchor="middle" font-size="10" font-weight="bold" fill="#333">${tick.sub}</text>` : ""}
          `,
        )
        .join("")}
      <text x="${pad + 3}" y="${pad - 7}" font-size="10" fill="#666">${max}</text>
    </svg>
  `;
}

function getRowsAtLeastSnp(rows) {
  const snp = rows.find((row) => row.key === "SNP");
  if (!snp) return rows;
  return rows.filter((row) => row.count >= snp.count);
}

function renderBars(container, rows, options = {}) {
  const { limit = 10, snpFloor = false, selectedKey = "" } = options;
  const visible = (snpFloor ? getRowsAtLeastSnp(rows) : rows).slice(0, limit);
  const max = Math.max(...visible.map((row) => row.count), 1);
  container.innerHTML = visible.length
    ? visible
        .map(
          (row) => {
            const isActive = row.key === selectedKey;
            return `
              <div class="bar-row${isActive ? " active" : ""}" data-key="${escapeHtml(row.key)}">
                <span class="bar-label" title="${escapeHtml(row.key)}">${escapeHtml(row.key)}</span>
                <span class="bar-track"><span class="bar-fill" style="width:${Math.max(3, (row.count / max) * 100)}%"></span></span>
                <span class="bar-value">${formatNumber.format(row.count)}</span>
              </div>
            `;
          }
        )
        .join("")
    : '<p class="chart-note">No matching data.</p>';
}

// A member name / constituency rendered as a clickable filter: clicking it fills the
// search with that text (see the table click handler), so you land on that MP's questions
// exactly as if you'd typed the name in.
function filterLink(text) {
  if (!text) return "-";
  const safe = escapeHtml(text);
  return `<span class="filter-link" data-filter="${safe}" role="button" tabindex="0" title="Show questions from ${safe}">${safe}</span>`;
}

function renderTable(items) {
  // A week of department-wide PQs runs to a few hundred rows, so the whole window fits
  // under this cap — you can scroll the lot without touching a filter.
  const limit = 500;
  const visible = items.slice(0, limit);
  answerByQid.clear();
  hideAnswerTip();
  const totalCount = state.summary?.totals?.questions || items.length;
  const share = isFiltered()
    ? ` · ${formatShare(items.length, totalCount)} of all ${formatNumber.format(totalCount)} PQs`
    : "";
  elements.resultsCount.textContent = `showing ${formatNumber.format(visible.length)} of ${formatNumber.format(items.length)}${share}`;
  
  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayStr = yesterday.toISOString().slice(0, 10);
  
  elements.table.innerHTML = visible
    .map(
      (question) => {
        const isOverdue = !question.answered && question.dateForAnswer && question.dateForAnswer < todayStr;
        let dueLabel = question.dateForAnswer ? shortDate(question.dateForAnswer) : "-";
        
        const indicators = [];
        if (question.isNamedDay) {
          indicators.push(`<span class="due-indicator named-day" title="Named Day">(ND)</span>`);
        }
        if (isOverdue) {
          indicators.push(`<span class="due-indicator overdue" title="Overdue">(O)</span>`);
        }
        
        const dueCellHtml = dueLabel + (indicators.length ? " " + indicators.join(" ") : "");

        const hasAnswer = question.answered && Boolean(question.answerText);
        if (hasAnswer) {
          // Stored text may be the list endpoint's ~250-char snippet; `full` says whether
          // it is the whole answer or whether the tooltip needs to go and fetch it.
          answerByQid.set(String(question.id), {
            text: question.answerText,
            full: Boolean(question.answerFull),
          });
        }

        let tabledHtml = escapeHtml(shortDate(question.dateTabled));
        if (question.dateTabled === todayStr) {
          tabledHtml = `<span class="tabled-badge today" title="Tabled Today">⚡ TODAY</span>`;
        } else if (question.dateTabled === yesterdayStr) {
          tabledHtml = `<span class="tabled-badge yesterday" title="Tabled Yesterday">YESTERDAY</span>`;
        }

        return `
          <tr>
            <td><a href="${escapeHtml(question.url)}">${escapeHtml(question.uin)}</a></td>
            <td style="white-space: nowrap;">${tabledHtml}</td>
            <td style="white-space: nowrap;">${dueCellHtml}</td>
            <td><span class="party-dot" title="${escapeHtml(question.member.party || question.member.partyAbbreviation || "Unknown")}">${partyEmoji(question)}</span> ${filterLink(question.member.name)}</td>
            <td>${filterLink(question.member.constituency)}</td>
            <td>${escapeHtml(question.region.nhsRegion || "-")}</td>
            <td class="question-cell">
              <button class="row-menu" type="button" data-row-menu="${escapeHtml(String(question.id))}" title="More — find similar questions" aria-label="Row actions">☰</button>
              <div class="question-heading">${escapeHtml(question.heading || "Written question")}</div>
              <div class="question-text">${questionTextHtml(question)}</div>
              <span class="status-pill ${question.answered ? "answered" : "unanswered"}${hasAnswer ? " has-answer-tip" : ""}"${hasAnswer ? ` data-qid="${escapeHtml(String(question.id))}"` : ""}>
                <span class="status-dot ${question.answered ? "green" : "amber"}"></span>
                ${question.answered ? "answered" : "unanswered"}
              </span>
            </td>
          </tr>
        `;
      }
    )
    .join("");
}

// ── Similar questions (BETA) ─────────────────────────────────────────────────
// TF-IDF cosine similarity over heading + question text, built lazily in the browser.
// Every PQ opens with the same formula ("To ask the Secretary of State…"), so that
// opener is stripped and IDF damps the rest of the shared boilerplate — what's left is
// the distinctive subject matter.
//
// Matches are drawn from answered PQs in the current Parliament only. An unanswered
// question has nothing to compare — the answer is the thing you came for — and the
// Parliament floor costs nothing today, since the dataset's window starts on its first
// sitting day (config.js `windowStart`). But that window is configurable, and a wording
// match against a PQ put to a different government under different policy reads as a
// comparator when it isn't one, so the floor is enforced here rather than inherited.
const CURRENT_PARLIAMENT_START = "2024-07-09"; // first sitting day after the 2024 election
const SIMILAR_STOPWORDS = new Set(
  `a an and any are as at be been being by for from has have how in into is it its of on or that the their
   them there these this those to was were what when where which who why will with would could should make
   made plans plan number many whether if ask asked secretary state department health social care steps
   taking take assessment recent potential impact he she his her they what`.split(/\s+/),
);
const PQ_OPENER = /^to ask the (secretary of state|minister)[^,]*,\s*/i;
const SIMILAR_MIN_SCORE = 0.12;
let similarityIndex = null;

function similarityTokens(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 2 && !SIMILAR_STOPWORDS.has(t));
}

function isSimilarCandidate(question) {
  if (!question.answered) return false;
  const date = question.dateTabled || "";
  return Boolean(date) && date >= CURRENT_PARLIAMENT_START;
}

function similarityTermFrequencies(question) {
  const body = String(question.questionText || "").replace(PQ_OPENER, "");
  const tf = new Map();
  for (const t of similarityTokens(`${question.heading || ""} ${body}`)) {
    tf.set(t, (tf.get(t) || 0) + 1);
  }
  return tf;
}

// TF-IDF weights, L2-normalised so a dot product between two vectors is their cosine.
function similarityVector(tf, df, total) {
  const vec = new Map();
  let norm = 0;
  for (const [t, f] of tf) {
    const weight = (1 + Math.log(f)) * Math.log(total / (1 + (df.get(t) || 0)));
    if (weight > 0) {
      vec.set(t, weight);
      norm += weight * weight;
    }
  }
  norm = Math.sqrt(norm) || 1;
  for (const [t, w] of vec) vec.set(t, w / norm);
  return vec;
}

function buildSimilarityIndex() {
  const questions = state.questions.filter(isSimilarCandidate);
  const frequencies = questions.map(similarityTermFrequencies);

  const df = new Map();
  for (const tf of frequencies) for (const t of tf.keys()) df.set(t, (df.get(t) || 0) + 1);

  const total = frequencies.length;
  const docs = questions.map((q, i) => ({ q, vec: similarityVector(frequencies[i], df, total) }));

  // Postings list: term → flat [docIndex, weight, …]. Department-wide, this corpus is
  // ~23,000 questions, and walking every one of them per lookup costs ~14ms; scoring only
  // the documents that share a term with the anchor brings that back under a millisecond.
  const postings = new Map();
  docs.forEach((d, i) => {
    for (const [t, w] of d.vec) {
      let list = postings.get(t);
      if (!list) postings.set(t, (list = []));
      list.push(i, w);
    }
  });

  // df and total are kept so a question outside the corpus can still be scored against it.
  similarityIndex = { docs, df, total, postings, sourceCount: state.questions.length,
    byId: new Map(docs.map((d) => [d.q.id, d])) };
}

// The dataset streams in chunks, so an index built while chunks are still landing is
// stale the moment the next one arrives. Rebuild whenever the corpus has grown.
function ensureSimilarityIndex() {
  if (!similarityIndex || similarityIndex.sourceCount !== state.questions.length) {
    buildSimilarityIndex();
  }
  return similarityIndex;
}

// Building the index over a department-wide corpus costs ~0.5s of main thread, so pay it
// in an idle slot once the chunks have finished streaming rather than on the first click.
function warmSimilarityIndex() {
  const build = () => ensureSimilarityIndex();
  if (typeof requestIdleCallback === "function") requestIdleCallback(build, { timeout: 3000 });
  else setTimeout(build, 1000);
}

function findSimilarQuestions(question, limit = 3) {
  const index = ensureSimilarityIndex();
  if (!index.total) return [];
  // The anchor is often the question still waiting for an answer, and may sit outside the
  // window besides — either way it can be absent from the corpus, so score it against
  // that corpus's IDF weights instead.
  const indexed = index.byId.get(question.id);
  const targetVec = indexed
    ? indexed.vec
    : similarityVector(similarityTermFrequencies(question), index.df, index.total);
  // Both sides are L2-normalised, so accumulating shared-term products per document
  // gives the cosine directly.
  const scores = new Map();
  for (const [t, w] of targetVec) {
    const list = index.postings.get(t);
    if (!list) continue;
    for (let i = 0; i < list.length; i += 2) {
      scores.set(list[i], (scores.get(list[i]) || 0) + w * list[i + 1]);
    }
  }

  const scored = [];
  for (const [docIndex, score] of scores) {
    if (score < SIMILAR_MIN_SCORE) continue;
    const d = index.docs[docIndex];
    if (d.q.id === question.id) continue;
    scored.push({ question: d.q, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit);
}

// ── Row menu → similar questions panel ───────────────────────────────────────
let openRowMenuId = null;

function closeSimilarPanel() {
  openRowMenuId = null;
  similarAnswerByQid.clear();
  hideAnswerTip();
  if (elements.similarPanel) elements.similarPanel.hidden = true;
}

function positionSimilarPanel(anchor) {
  const panel = elements.similarPanel;
  const margin = 8;
  const gap = 6;
  const vw = document.documentElement.clientWidth;
  const vh = window.innerHeight;
  const r = anchor.getBoundingClientRect();

  const spaceBelow = vh - r.bottom - gap - margin;
  const spaceAbove = r.top - gap - margin;
  const below = spaceBelow >= spaceAbove;
  panel.style.maxHeight = `${Math.max(160, Math.min(below ? spaceBelow : spaceAbove, Math.round(vh * 0.7)))}px`;

  const h = panel.offsetHeight;
  const w = panel.offsetWidth;
  let top = below ? r.bottom + gap : r.top - gap - h;
  top = Math.max(margin, Math.min(top, vh - h - margin));
  // Right-align to the button, since it sits at the row's right edge.
  let left = Math.min(r.right - w, vw - w - margin);
  left = Math.max(margin, left);
  panel.style.top = `${Math.round(top)}px`;
  panel.style.left = `${Math.round(left)}px`;
}

// The panel always shows the question as tabled, pro forma and all: the table's short
// mode is a setting for the table, and a comparator is easier to trust when you can see
// the whole wording. (Matching still strips the formula — that is scoring, not display.)
function similarQuestionText(question) {
  const text = String(question.questionText || "");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function openSimilarPanel(anchor, question) {
  const panel = elements.similarPanel;
  if (!panel) return;
  const hits = findSimilarQuestions(question, 3);

  // Feed the hover popup the same way renderTable does, so the answer is readable here
  // rather than only on parliament.uk. `full` says whether the stored text is the whole
  // answer or the list endpoint's extract, which the popup then completes from the API.
  similarAnswerByQid.clear();
  for (const h of hits) {
    if (h.question.answerText) {
      similarAnswerByQid.set(String(h.question.id), {
        text: h.question.answerText,
        full: Boolean(h.question.answerFull),
      });
    }
  }

  const rows = hits.length
    ? hits
        .map(
          (h) => `
            <li class="similar-item">
              <div class="similar-meta">
                <span class="similar-uin">UIN ${escapeHtml(h.question.uin)}</span>
                <span>${escapeHtml(shortDate(h.question.dateTabled))}</span>
                <span>${escapeHtml(h.question.member.name || "-")}</span>
                <span class="similar-score" title="Similarity score">${Math.round(h.score * 100)}%</span>
              </div>
              <div class="similar-heading">${escapeHtml(h.question.heading || "Written question")}</div>
              <div class="similar-text">${escapeHtml(similarQuestionText(h.question))}</div>
              <div class="similar-actions">
                ${
                  h.question.answerText
                    ? `<span class="status-pill answered has-answer-tip" data-qid="${escapeHtml(String(h.question.id))}" title="Hover to read the answer">
                         <span class="status-dot green"></span>
                         read answer
                       </span>`
                    : ""
                }
                <a class="similar-link" href="${escapeHtml(h.question.url)}" target="_blank" rel="noopener noreferrer">View on parliament.uk ↗</a>
              </div>
            </li>`,
        )
        .join("")
    : `<li class="similar-empty">No closely similar answered questions in the current Parliament.</li>`;

  panel.innerHTML = `
    <div class="similar-head">
      <span>Similar questions <span class="beta-badge">BETA</span></span>
      <button type="button" class="similar-close" aria-label="Close">✕</button>
    </div>
    <p class="similar-note">Answered questions from the current Parliament only (from ${escapeHtml(shortDate(CURRENT_PARLIAMENT_START))}). Matched on wording, not meaning — treat as a starting point, not a definitive set.</p>
    <ul class="similar-list">${rows}</ul>`;

  panel.hidden = false;
  positionSimilarPanel(anchor);
  openRowMenuId = question.id;
}

document.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-row-menu]");
  if (btn) {
    event.stopPropagation();
    const id = Number(btn.dataset.rowMenu);
    if (openRowMenuId === id) return closeSimilarPanel();
    const question = state.questions.find((q) => q.id === id);
    if (question) openSimilarPanel(btn, question);
    return;
  }
  if (
    elements.similarPanel &&
    !elements.similarPanel.hidden &&
    !event.target.closest("#similar-panel") &&
    !event.target.closest("#answer-tooltip")
  ) {
    closeSimilarPanel();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeSimilarPanel();
});

if (elements.similarPanel) {
  elements.similarPanel.addEventListener("click", (event) => {
    if (event.target.closest(".similar-close")) closeSimilarPanel();
  });
}

// The panel is position:fixed against a button in a scrolling table, so it can't follow
// its anchor — close it rather than leave it pointing at the wrong row. Scrolling inside
// the panel, or inside the answer popup it opened, is the reader working through a
// result, so neither counts.
window.addEventListener("resize", closeSimilarPanel);
window.addEventListener(
  "scroll",
  (event) => {
    const target = event.target;
    if (target instanceof Node) {
      if (elements.similarPanel && elements.similarPanel.contains(target)) return;
      if (elements.answerTooltip && elements.answerTooltip.contains(target)) return;
    }
    closeSimilarPanel();
  },
  true,
);


// ── Answer hover tooltip ─────────────────────────────────────────────────────
// A single body-level (position:fixed) popup, so it escapes the table's overflow
// clipping and can be positioned anywhere in the viewport.
let answerTipPill = null;
let answerTipHideTimer = null;

// Append a string to `parent`, turning bare http(s) URLs into real, clickable links.
// Built with DOM nodes (no innerHTML), so the API-derived text can't inject markup.
function appendTextWithLinks(parent, text) {
  const urlRe = /https?:\/\/[^\s<>]+/g;
  let last = 0;
  let m;
  while ((m = urlRe.exec(text)) !== null) {
    let url = m[0];
    // Don't swallow trailing sentence punctuation into the link.
    const trailing = (url.match(/[.,;:!?)\]}'"]+$/) || [""])[0];
    if (trailing) url = url.slice(0, url.length - trailing.length);
    if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
    const a = document.createElement("a");
    a.href = url;
    a.textContent = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    parent.appendChild(a);
    if (trailing) parent.appendChild(document.createTextNode(trailing));
    last = m.index + m[0].length;
  }
  if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
}

// ── Copy the answer ──────────────────────────────────────────────────────────
// The popup is the only place the answer appears in full on this page, so it needs a
// way out: one button, copying exactly the text currently on screen.
let answerTipText = "";
let answerCopyResetTimer = null;

function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  // Plain http (a local file server, say) has no async clipboard API.
  return new Promise((resolve, reject) => {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    document.body.appendChild(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    copied ? resolve() : reject(new Error("copy rejected"));
  });
}

// Built once and kept: the popup re-renders when a longer answer arrives, and rebuilding
// the button there would wipe the "Copied" confirmation out from under the reader. The
// handler reads answerTipText at click time, so it always copies what is on screen.
let answerTipBody = null;
let answerCopyButton = null;

// Two stacked sheets for "copy", a tick for "copied" — drawn in currentColor at the
// same weight as the rest of the interface, so the popup stays uncluttered.
const COPY_ICON_SVG = `
  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
       stroke-width="1.8" stroke-linecap="square" stroke-linejoin="miter" aria-hidden="true">
    <path d="M9 8H4v12h11v-4" />
    <path d="M9 4h7l5 5v7H9z" />
    <path d="M16 4v5h5" />
    <path d="M11.5 11.5h7M11.5 14h7" />
  </svg>`;

const COPIED_ICON_SVG = `
  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
       stroke-width="2.2" stroke-linecap="square" stroke-linejoin="miter" aria-hidden="true">
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </svg>`;

function setAnswerCopyState(button, state) {
  button.innerHTML = state === "copied" ? COPIED_ICON_SVG : COPY_ICON_SVG;
  button.classList.toggle("copied", state === "copied");
  button.classList.toggle("failed", state === "failed");
  const label =
    state === "copied"
      ? "Answer copied"
      : state === "failed"
        ? "Copy failed — select the text and press Ctrl+C"
        : "Copy this answer";
  button.title = label;
  button.setAttribute("aria-label", label);
}

function resetAnswerCopyButton() {
  clearTimeout(answerCopyResetTimer);
  if (!answerCopyButton) return;
  setAnswerCopyState(answerCopyButton, "copy");
}

function buildAnswerCopyButton() {
  const row = document.createElement("div");
  row.className = "answer-tip-actions";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "answer-copy";
  setAnswerCopyState(button, "copy");
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    copyTextToClipboard(answerTipText)
      .then(() => setAnswerCopyState(button, "copied"))
      .catch(() => setAnswerCopyState(button, "failed"))
      .finally(() => {
        clearTimeout(answerCopyResetTimer);
        answerCopyResetTimer = setTimeout(() => setAnswerCopyState(button, "copy"), 1600);
      });
  });
  row.appendChild(button);
  answerCopyButton = button;
  return row;
}

// The popup keeps a fixed shape: a body the content replaces, then the copy strip.
function ensureAnswerTipChrome() {
  const tip = elements.answerTooltip;
  if (answerTipBody && tip.contains(answerTipBody)) return;
  tip.textContent = "";
  answerTipBody = document.createElement("div");
  answerTipBody.className = "answer-tip-body";
  tip.appendChild(answerTipBody);
  tip.appendChild(buildAnswerCopyButton());
}

function setAnswerTipContent(text, loadingMore = false, note = "") {
  ensureAnswerTipChrome();
  const tip = answerTipBody;
  tip.textContent = "";
  answerTipText = String(text);
  // stripHtml separates paragraphs with newlines — render them as real paragraphs
  // (with spacing) rather than a wall of pre-wrapped text.
  const paras = String(text).split(/\n+/).map((s) => s.trim()).filter(Boolean);
  const blocks = paras.length ? paras : [String(text)];
  for (const p of blocks) {
    const el = document.createElement("p");
    appendTextWithLinks(el, p);
    tip.appendChild(el);
  }
  if (loadingMore || note) {
    const status = document.createElement("p");
    status.className = "answer-tip-status";
    status.textContent = note || "Loading the full answer…";
    tip.appendChild(status);
  }
}

function positionAnswerTip(pill) {
  const tip = elements.answerTooltip;
  const margin = 8;
  const gap = 8;
  const vw = document.documentElement.clientWidth;
  const vh = window.innerHeight;
  const r = pill.getBoundingClientRect();

  const spaceAbove = r.top - gap - margin;
  const spaceBelow = vh - r.bottom - gap - margin;
  const placeAbove = spaceAbove > spaceBelow;

  // Cap the height to the room on the chosen side so the box never overlaps the
  // pill or spills off-screen; long answers scroll inside.
  const avail = Math.max(120, placeAbove ? spaceAbove : spaceBelow);
  tip.style.maxHeight = Math.min(avail, Math.round(vh * 0.7)) + "px";

  const th = tip.offsetHeight;
  const tw = tip.offsetWidth;
  let top = placeAbove ? r.top - gap - th : r.bottom + gap;
  top = Math.max(margin, Math.min(top, vh - th - margin));
  let left = Math.min(r.left, vw - tw - margin);
  left = Math.max(margin, left);

  tip.style.left = `${Math.round(left)}px`;
  tip.style.top = `${Math.round(top)}px`;
}

// ── Full answers, fetched on demand ──────────────────────────────────────────
// The dataset stores only the list endpoint's ~250-char answer snippet: shipping all
// 22,000 full answers would double the payload and take hours to collect (config.js).
// The Parliament API sends `access-control-allow-origin: *`, so the full text is one
// public request away, made the moment someone actually wants to read it. Cached for
// the session, so hovering the same answer twice costs nothing.
const QUESTION_DETAIL_ENDPOINT =
  "https://questions-statements-api.parliament.uk/api/writtenquestions/questions";
const fullAnswerCache = new Map(); // qid -> full answer text
const inFlightAnswers = new Map(); // qid -> Promise

function stripHtml(value) {
  return String(value || "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function fetchFullAnswer(qid) {
  if (fullAnswerCache.has(qid)) return Promise.resolve(fullAnswerCache.get(qid));
  if (inFlightAnswers.has(qid)) return inFlightAnswers.get(qid);

  const request = fetch(`${QUESTION_DETAIL_ENDPOINT}/${encodeURIComponent(qid)}`)
    .then((response) => {
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response.json();
    })
    .then((payload) => {
      const detail = payload.value || payload;
      const text = stripHtml(detail.answerText);
      if (text) fullAnswerCache.set(qid, text);
      return text;
    })
    .finally(() => inFlightAnswers.delete(qid));

  inFlightAnswers.set(qid, request);
  return request;
}

// ── Export to Excel ──────────────────────────────────────────────────────────
// Downloads the questions currently in scope as an .xlsx. Full answers aren't stored
// (they're fetched on hover — see fetchFullAnswer), so the export first pulls the full
// answer for every answered question in scope, paced at a rate the Parliament API
// tolerates, reusing anything already fetched this session. A row whose answer can't be
// fetched falls back to the stored ~250-char extract and is flagged in the file.
const EXPORT_ANSWER_CONCURRENCY = 3; // parallel detail requests (concurrency 8 got a Cloudflare ban)
const EXPORT_ANSWER_DELAY_MS = 200; // per-worker pause between requests
const EXPORT_CONFIRM_FETCH_OVER = 400; // ask before a fetch bigger than this (it takes minutes)
const XLSX_SRC = "scripts/vendor/xlsx.full.min.js";

// SheetJS is ~950KB, so it is loaded only on the first export rather than on every page view.
let xlsxLibPromise = null;
function loadXlsxLib() {
  if (window.XLSX) return Promise.resolve(window.XLSX);
  if (xlsxLibPromise) return xlsxLibPromise;
  xlsxLibPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = XLSX_SRC;
    script.onload = () =>
      window.XLSX ? resolve(window.XLSX) : reject(new Error("spreadsheet library failed to initialise"));
    script.onerror = () => reject(new Error("could not load the spreadsheet library"));
    document.head.appendChild(script);
  });
  return xlsxLibPromise;
}

function answerNeedsFetch(q) {
  return q.answered && q.id != null && !q.answerFull && !fullAnswerCache.has(String(q.id));
}

// Fetch full answers for the answered questions in `questions`, paced. Failures are
// tolerated (the row keeps its extract); onProgress(done, total) drives the button label.
async function fetchAnswersForExport(questions, onProgress) {
  const targets = questions.filter(answerNeedsFetch);
  const total = targets.length;
  if (!total) return;

  let cursor = 0;
  let done = 0;
  async function worker() {
    while (cursor < targets.length) {
      const q = targets[cursor];
      cursor += 1;
      try {
        await fetchFullAnswer(String(q.id));
      } catch {
        /* keep the stored extract for this row */
      }
      done += 1;
      if (onProgress) onProgress(done, total);
      if (EXPORT_ANSWER_DELAY_MS) {
        await new Promise((resolve) => setTimeout(resolve, EXPORT_ANSWER_DELAY_MS));
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(EXPORT_ANSWER_CONCURRENCY, total) }, worker));
}

// The best answer text we hold for a question, and whether it is the complete answer.
function answerForExport(q) {
  if (q.answered && q.answerFull && q.answerText) return { text: q.answerText, complete: true };
  const cached = fullAnswerCache.get(String(q.id));
  if (cached) return { text: cached, complete: true };
  if (q.answered) return { text: q.answerText || "", complete: false }; // extract only, or none held
  return { text: "", complete: true }; // unanswered — nothing to complete
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

// One spreadsheet row per question. Key order here IS the column order in the file.
function exportRow(q, todayStr) {
  const answer = answerForExport(q);
  const overdue = !q.answered && q.dateForAnswer && q.dateForAnswer < todayStr;
  return {
    UIN: q.uin || "",
    "Date tabled": q.dateTabled || "",
    "Date due": q.dateForAnswer || "",
    "Date answered": q.dateAnswered || "",
    Status: q.answered ? "Answered" : "Unanswered",
    Overdue: q.answered ? "" : yesNo(overdue),
    "Named day": yesNo(q.isNamedDay),
    Subject: q.topic || "",
    Member: q.member?.name || "",
    Party: q.member?.party || q.member?.partyAbbreviation || "",
    Constituency: q.member?.constituency || "",
    Nation: q.region?.nation || "",
    "NHS region": q.region?.nhsRegion || "",
    Heading: q.heading || "",
    Question: q.questionText || "",
    Answer: answer.text,
    "Answer complete": q.answered ? yesNo(answer.complete) : "",
    URL: q.url || "",
  };
}

function exportSlug(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

// Short filename fragment describing the active filters, e.g. "dental-services_lab".
function exportScopeSlug() {
  const parts = [
    state.selectedTopic,
    state.party,
    state.region,
    state.answer,
    state.selectedBucket,
    state.query.trim(),
  ]
    .map(exportSlug)
    .filter(Boolean);
  return parts.join("_") || "all";
}

// Human-readable filter list for the About sheet.
function exportScopeDescription() {
  const parts = [];
  if (state.query.trim()) {
    parts.push(
      `search: "${state.query.trim()}"${state.searchQuestionOnly ? " (question text only)" : ""}`,
    );
  }
  if (state.selectedTopic) parts.push(`subject: ${state.selectedTopic}`);
  if (state.party) parts.push(`party: ${state.party}`);
  if (state.region) parts.push(`NHS region: ${state.region}`);
  if (state.answer) parts.push(`answer status: ${state.answer}`);
  if (state.selectedBucket) parts.push(`${state.bucketMode}: ${bucketLabel(state.selectedBucket)}`);
  return parts.length ? parts.join("; ") : "none (every question in the current dataset)";
}

let exportBusy = false;
function setExportBusy(busy, label) {
  exportBusy = busy;
  if (!elements.exportButton) return;
  elements.exportButton.disabled = busy;
  const span = elements.exportButton.querySelector(".btn-export-label");
  if (span) span.textContent = label;
}

function buildExportWorkbook(XLSX, rows) {
  const todayStr = new Date().toISOString().slice(0, 10);
  const dataRows = rows.map((q) => exportRow(q, todayStr));

  const ws = XLSX.utils.json_to_sheet(dataRows);
  // Column widths, in the key order of exportRow().
  ws["!cols"] = [8, 12, 12, 12, 11, 8, 10, 22, 22, 8, 26, 14, 22, 30, 60, 90, 9, 46].map((wch) => ({
    wch,
  }));
  ws["!autofilter"] = {
    ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: { r: dataRows.length, c: 17 } }),
  };

  const answered = rows.filter((q) => q.answered).length;
  const about = [
    [`${VERTICAL.brandTitle} — data export`],
    [],
    ["Generated", new Date().toLocaleString("en-GB")],
    ["Scope (filters)", exportScopeDescription()],
    ["Questions in scope", rows.length],
    ["Answered / unanswered", `${answered} / ${rows.length - answered}`],
    [],
    ["Source", "UK Parliament Written Questions API (questions-statements-api.parliament.uk)"],
    ["Source scope", `${VERTICAL.house} written questions, answering body ${VERTICAL.answeringBodies}`],
    [
      "Note on answers",
      "Full answer text is fetched from Parliament's per-question detail endpoint at export time. Where a fetch did not succeed, the stored ~250-character extract is used instead — see the 'Answer complete' column.",
    ],
  ];
  const wsAbout = XLSX.utils.aoa_to_sheet(about);
  wsAbout["!cols"] = [{ wch: 22 }, { wch: 96 }];

  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Questions");
  XLSX.utils.book_append_sheet(wb, wsAbout, "About");
  return { wb, todayStr };
}

async function exportInScopeToXlsx() {
  if (exportBusy) return;
  const rows = getFilteredQuestions();
  if (!rows.length) {
    window.alert("No questions are in scope to export. Adjust the filters and try again.");
    return;
  }

  const needFetch = rows.filter(answerNeedsFetch).length;
  if (needFetch > EXPORT_CONFIRM_FETCH_OVER) {
    const mins = Math.max(1, Math.ceil((needFetch * 0.8) / EXPORT_ANSWER_CONCURRENCY / 60));
    const ok = window.confirm(
      `This export will fetch ${formatNumber.format(needFetch)} full answers from the Parliament API, ` +
        `which may take around ${mins} minute${mins === 1 ? "" : "s"}. Continue?`,
    );
    if (!ok) return;
  }

  setExportBusy(true, "Preparing…");
  try {
    const [XLSX] = await Promise.all([
      loadXlsxLib(),
      fetchAnswersForExport(rows, (done, total) =>
        setExportBusy(true, `Fetching answers ${done}/${total}…`),
      ),
    ]);

    setExportBusy(true, "Building file…");
    const { wb, todayStr } = buildExportWorkbook(XLSX, rows);
    XLSX.writeFile(wb, `commons-pqs_${exportScopeSlug()}_${todayStr}.xlsx`);

    setExportBusy(false, "Exported ✓");
    setTimeout(() => setExportBusy(false, "Export to Excel"), 2500);
  } catch (error) {
    console.error(error);
    window.alert(`Export failed: ${error.message || error}`);
    setExportBusy(false, "Export to Excel");
  }
}

function showAnswerTip(pill) {
  const qid = pill.getAttribute("data-qid") || "";
  const entry = answerByQid.get(qid) || similarAnswerByQid.get(qid);
  if (!entry) return;
  clearTimeout(answerTipHideTimer);
  answerTipPill = pill;

  // Show what we already have straight away — a snippet now beats a spinner.
  const cached = fullAnswerCache.get(qid);
  const known = cached || entry.text;
  setAnswerTipContent(known, !entry.full && !cached);
  elements.answerTooltip.scrollTop = 0;
  elements.answerTooltip.classList.add("visible");
  positionAnswerTip(pill);

  if (entry.full || cached) return;

  fetchFullAnswer(qid)
    .then((text) => {
      // The pointer may have moved on to another answer while this was in flight.
      if (answerTipPill !== pill || !text) return;
      setAnswerTipContent(text);
      positionAnswerTip(pill);
    })
    .catch(() => {
      if (answerTipPill !== pill) return;
      setAnswerTipContent(entry.text, false, "Could not load the full answer — showing the stored extract.");
      positionAnswerTip(pill);
    });
}

function hideAnswerTip() {
  clearTimeout(answerTipHideTimer);
  answerTipPill = null;
  resetAnswerCopyButton();
  if (elements.answerTooltip) elements.answerTooltip.classList.remove("visible");
}

function scheduleHideAnswerTip() {
  clearTimeout(answerTipHideTimer);
  answerTipHideTimer = setTimeout(hideAnswerTip, 120);
}

// Clicking (or Enter/Space on) a member name or constituency in the table fills the
// search with that text and filters — landing you on that MP's questions.
function applyFilterFromLink(link) {
  const term = link.getAttribute("data-filter") || "";
  state.query = term;
  if (elements.search) elements.search.value = term;
  render();
}

if (elements.table) {
  elements.table.addEventListener("click", (event) => {
    const link = event.target.closest(".filter-link");
    if (!link || !elements.table.contains(link)) return;
    event.preventDefault();
    applyFilterFromLink(link);
  });
  elements.table.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const link = event.target.closest(".filter-link");
    if (!link || !elements.table.contains(link)) return;
    event.preventDefault();
    applyFilterFromLink(link);
  });
}

// Any container holding `.has-answer-tip` pills can opt into the hover popup — the
// questions table, and the similar-questions panel.
function bindAnswerTipHover(container) {
  if (!elements.answerTooltip || !container) return;
  container.addEventListener("mouseover", (event) => {
    const pill = event.target.closest(".has-answer-tip");
    if (!pill || !container.contains(pill)) return;
    if (pill === answerTipPill) {
      clearTimeout(answerTipHideTimer);
      return;
    }
    showAnswerTip(pill);
  });
  container.addEventListener("mouseout", (event) => {
    const pill = event.target.closest(".has-answer-tip");
    if (!pill) return;
    const to = event.relatedTarget;
    if (to && (pill.contains(to) || elements.answerTooltip.contains(to))) return;
    scheduleHideAnswerTip();
  });
}

if (elements.answerTooltip && elements.table) {
  bindAnswerTipHover(elements.table);
  bindAnswerTipHover(elements.similarPanel);
  // Hover intent: moving the cursor into the tooltip (to read/scroll) keeps it open.
  elements.answerTooltip.addEventListener("mouseenter", () => clearTimeout(answerTipHideTimer));
  elements.answerTooltip.addEventListener("mouseleave", scheduleHideAnswerTip);
  // Dismiss on page scroll/resize, but ignore scrolling *inside* the tooltip.
  window.addEventListener(
    "scroll",
    (event) => {
      if (event.target !== elements.answerTooltip) hideAnswerTip();
    },
    true,
  );
  window.addEventListener("resize", hideAnswerTip);
}

function render() {
  const mode = resolveBucketMode();
  if (mode !== state.bucketMode) {
    state.bucketMode = mode;
    state.selectedBucket = ""; // a key from the old mode ("2026-07-08") can't match the new one
  }

  const filtered = getFilteredQuestions();
  const lineChartFiltered = getFilteredQuestions(true, false, false, false);
  const themeChartFiltered = getFilteredQuestions(false, true, false, false);
  const partyChartFiltered = getFilteredQuestions(false, false, true, false);
  const regionChartFiltered = getFilteredQuestions(false, false, false, true);

  renderScopeStatus(filtered.length);
  renderMetrics(filtered);
  renderLineChart(lineChartFiltered);
  renderBars(elements.themeChart, getTopicCounts(themeChartFiltered), {
    limit: 100,
    selectedKey: state.selectedTopic
  });
  renderBars(elements.partyChart, countBy(partyChartFiltered, (question) => question.member.partyAbbreviation || question.member.party), {
    limit: 30,
    snpFloor: true,
    selectedKey: state.party
  });
  renderBars(elements.regionChart, countBy(regionChartFiltered, (question) => question.region.nhsRegion), {
    limit: 12,
    selectedKey: state.region
  });
  renderTable(filtered);
}

// ── Progressive load progress pill ───────────────────────────────────────────
function showLoadProgress(loaded, total) {
  let el = document.getElementById("load-progress");
  if (!el) {
    el = document.createElement("div");
    el.id = "load-progress";
    document.body.appendChild(el);
  }
  el.textContent = total
    ? `Loading all questions… ${formatNumber.format(loaded)} of ${formatNumber.format(total)}`
    : `Loading all questions… ${formatNumber.format(loaded)}`;
  el.classList.add("visible");
}

function hideLoadProgress() {
  const el = document.getElementById("load-progress");
  if (el) el.classList.remove("visible");
}

// Re-rendering the whole dashboard on every chunk would be janky, so coalesce: at most
// one full re-render per 350ms while chunks are streaming in.
let progressiveRenderScheduled = false;
function scheduleProgressiveRender() {
  if (progressiveRenderScheduled) return;
  progressiveRenderScheduled = true;
  setTimeout(() => {
    progressiveRenderScheduled = false;
    renderSelects();
    render();
  }, 350);
}

// Fetch, decrypt and append questions chunks 1..n-1 after the first page is already on
// screen. Order is preserved (chunks are written newest-first), so a plain push keeps the
// global sort. Failures skip a chunk rather than sinking the whole load.
async function loadRemainingChunks(password, chunkCount) {
  if (chunkCount <= 1) {
    warmSimilarityIndex();
    return;
  }
  const total = state.summary?.totals?.questions || 0;
  showLoadProgress(state.questions.length, total);

  for (let i = 1; i < chunkCount; i += 1) {
    try {
      const resp = await fetch(`data/${VERTICAL.id}/questions-${i}.json.enc`, { cache: "no-store" });
      if (!resp.ok) continue;
      const json = await decryptContainer(await resp.arrayBuffer(), password);
      state.questions.push(...(JSON.parse(json).questions || []));
      showLoadProgress(state.questions.length, total);
      scheduleProgressiveRender();
    } catch (err) {
      console.error(`Questions chunk ${i} failed to load:`, err);
    }
  }

  hideLoadProgress();
  renderSelects();
  render();
  warmSimilarityIndex();
}

async function loadData() {
  // Chunked encrypted mode: an unencrypted manifest lists the chunk count; the app
  // decrypts the summary + first chunk, paints, then streams the rest (loadRemainingChunks).
  const manifestResp = await fetch(`data/${VERTICAL.id}/questions-index.json`, { cache: "no-store" });
  const encSummaryResp = await fetch(`data/${VERTICAL.id}/summary.json.enc`, { cache: "no-store" });

  if (manifestResp.ok && encSummaryResp.ok) {
    const manifest = await manifestResp.json();
    const chunkCount = Math.max(1, manifest.chunks || 1);
    const summaryBuf = await encSummaryResp.arrayBuffer();
    const chunk0Buf = await (
      await fetch(`data/${VERTICAL.id}/questions-0.json.enc`, { cache: "no-store" })
    ).arrayBuffer();

    while (true) {
      const password = await passwordReady;
      try {
        const [summaryJson, chunk0Json] = await Promise.all([
          decryptContainer(summaryBuf, password),
          decryptContainer(chunk0Buf, password),
        ]);
        state.summary = JSON.parse(summaryJson);
        state.questions = JSON.parse(chunk0Json).questions || [];

        // Success — store password, reveal the page, then fill in the rest in the background.
        sessionStorage.setItem("pq-auth-ok", password);
        const overlay = document.getElementById("auth-overlay");
        if (overlay) overlay.remove();
        document.querySelector(".page").style.display = "";
        loadRemainingChunks(password, chunkCount);
        return;
      } catch {
        // Decryption failed. Usually a wrong password, but also happens when a stored
        // session password has gone stale (the data was re-encrypted) — in which case
        // there is no overlay yet, so build one rather than dead-ending on a blank page.
        // Either way, drop the bad stored password and wait for a fresh attempt.
        sessionStorage.removeItem("pq-auth-ok");
        if (!document.getElementById("auth-overlay")) buildAuthOverlay();
        const overlay = document.getElementById("auth-overlay");
        if (overlay) {
          document.getElementById("auth-error").style.display = "block";
          document.getElementById("auth-btn").textContent = "Enter";
          document.getElementById("auth-input").value = "";
          document.getElementById("auth-input").focus();
          await awaitNextPassword();
          continue;
        }
        throw new Error("Decryption failed.");
      }
    }
  }

  // Plaintext fallback (local dev without encryption): single questions.json, no chunks.
  const [summaryResponse, questionsResponse] = await Promise.all([
    fetch(`data/${VERTICAL.id}/summary.json`, { cache: "no-store" }),
    fetch(`data/${VERTICAL.id}/questions.json`, { cache: "no-store" }),
  ]);
  if (!summaryResponse.ok || !questionsResponse.ok) {
    throw new Error("Dashboard data could not be loaded.");
  }
  state.summary = await summaryResponse.json();
  const questionsPayload = await questionsResponse.json();
  state.questions = questionsPayload.questions || [];

  const overlay = document.getElementById("auth-overlay");
  if (overlay) overlay.remove();
  document.querySelector(".page").style.display = "";
}

elements.search.addEventListener("input", (event) => {
  state.query = event.target.value;
  render();
});

if (elements.searchQuestionOnly) {
  elements.searchQuestionOnly.addEventListener("change", (event) => {
    state.searchQuestionOnly = event.target.checked;
    render();
  });
}



elements.partyFilter.addEventListener("change", (event) => {
  state.party = event.target.value;
  render();
});

elements.regionFilter.addEventListener("change", (event) => {
  state.region = event.target.value;
  render();
});

elements.answerFilter.addEventListener("change", (event) => {
  state.answer = event.target.value;
  render();
});

elements.themeChart.addEventListener("click", (event) => {
  const row = event.target.closest(".bar-row");
  if (!row) return;

  // Selecting a bar is a filter action, not a click "outside" the day selection — and the
  // document-level deselect can't tell, because render() detaches this row before it runs.
  event.stopPropagation();

  const topic = row.getAttribute("data-key");
  if (!topic) return;

  if (state.selectedTopic === topic) {
    state.selectedTopic = "";
  } else {
    state.selectedTopic = topic;
  }
  render();
});

elements.partyChart.addEventListener("click", (event) => {
  const row = event.target.closest(".bar-row");
  if (!row) return;
  event.stopPropagation();

  const party = row.getAttribute("data-key");
  if (!party) return;

  if (state.party === party) {
    state.party = "";
  } else {
    state.party = party;
  }
  elements.partyFilter.value = state.party;
  render();
});

elements.regionChart.addEventListener("click", (event) => {
  const row = event.target.closest(".bar-row");
  if (!row) return;
  event.stopPropagation();

  const region = row.getAttribute("data-key");
  if (!region) return;

  if (state.region === region) {
    state.region = "";
  } else {
    state.region = region;
  }
  elements.regionFilter.value = state.region;
  render();
});

if (elements.todayFilter) {
  elements.todayFilter.addEventListener("click", () => {
    const latest = latestTabledDate();
    if (!latest) return;
    // Toggle: a second click clears it.
    state.tabledOn = state.tabledOn === latest ? "" : latest;
    render();
  });
}

if (elements.shortMode) {
  elements.shortMode.addEventListener("change", (event) => {
    state.shortMode = event.target.checked;
    render();
  });
}

elements.resetFilters.addEventListener("click", () => {
  state.query = "";
  state.party = "";
  state.region = "";
  state.answer = "";
  state.selectedBucket = "";
  state.selectedTopic = "";
  state.tabledOn = "";

  elements.search.value = "";
  if (elements.searchQuestionOnly) {
    elements.searchQuestionOnly.checked = true;
  }
  state.searchQuestionOnly = true;

  elements.partyFilter.value = "";
  elements.regionFilter.value = "";
  elements.answerFilter.value = "";

  renderSelects();
  render();
});

if (elements.exportButton) {
  elements.exportButton.addEventListener("click", exportInScopeToXlsx);
}

elements.monthlyChart.addEventListener("mouseover", (event) => {
  const dot = event.target.closest(".data-point");
  if (!dot) return;
  const index = parseInt(dot.getAttribute("data-index"), 10);
  const point = state.chartPoints[index];
  if (!point) return;

  const titleText = bucketLabel(point.key, true);

  const rowsHtml = point.themeCounts
    .map(
      (theme) => `
      <div class="chart-tooltip-row">
        <span class="chart-tooltip-label">${escapeHtml(theme.key)}</span>
        <span class="chart-tooltip-value">${formatNumber.format(theme.count)}</span>
      </div>
    `
    )
    .join("");

  elements.tooltip.innerHTML = `
    <div class="chart-tooltip-title">${titleText}</div>
    <div class="chart-tooltip-row" style="border-bottom: 1px dashed var(--line); padding-bottom: 3px; margin-bottom: 5px;">
      <span class="chart-tooltip-label" style="font-weight: bold; color: var(--text);">Total PQs</span>
      <span class="chart-tooltip-value">${formatNumber.format(point.count)}</span>
    </div>
    ${rowsHtml}
  `;
  elements.tooltip.style.opacity = "1";
});

elements.monthlyChart.addEventListener("mousemove", (event) => {
  elements.tooltip.style.left = `${event.pageX + 12}px`;
  elements.tooltip.style.top = `${event.pageY + 12}px`;
});

elements.monthlyChart.addEventListener("mouseout", (event) => {
  const dot = event.target.closest(".data-point");
  if (!dot) return;
  elements.tooltip.style.opacity = "0";
});

elements.monthlyChart.addEventListener("click", (event) => {
  event.stopPropagation(); // Prevent document click handler from immediately clearing state.selectedBucket
  if (state.chartPoints.length === 0) return;

  // Direct dot click (or programmatic test events)
  const dot = event.target.closest(".data-point");
  if (dot) {
    const index = parseInt(dot.getAttribute("data-index"), 10);
    const point = state.chartPoints[index];
    if (point) {
      state.selectedBucket = state.selectedBucket === point.key ? "" : point.key;
      render();
      return;
    }
  }

  // Fallback: Click anywhere on column coordinates
  const svg = elements.monthlyChart.querySelector("svg");
  if (!svg) return;

  const rect = svg.getBoundingClientRect();
  const clickXRel = event.clientX - rect.left;
  const clickYRel = event.clientY - rect.top;
  
  const viewBoxAttr = svg.getAttribute("viewBox");
  const viewBoxParts = viewBoxAttr ? viewBoxAttr.split(/\s+/) : [];
  const viewBoxWidth = viewBoxParts[2] ? parseFloat(viewBoxParts[2]) : 760;
  const viewBoxHeight = viewBoxParts[3] ? parseFloat(viewBoxParts[3]) : 220;
  
  const svgX = (clickXRel / rect.width) * viewBoxWidth;
  const svgY = (clickYRel / rect.height) * viewBoxHeight;

  const pad = 28;
  const buffer = 10;

  // Check if click is outside plot area boundaries (e.g., margins/padding)
  if (
    svgX < pad - buffer ||
    svgX > (viewBoxWidth - pad) + buffer ||
    svgY < pad - buffer ||
    svgY > (viewBoxHeight - pad) + buffer
  ) {
    state.selectedBucket = "";
    render();
    return;
  }

  let closestPoint = null;
  let minDistance = Infinity;

  for (const point of state.chartPoints) {
    const dist = Math.abs(point.x - svgX);
    if (dist < minDistance) {
      minDistance = dist;
      closestPoint = point;
    }
  }

  if (closestPoint) {
    if (svgX >= pad - 10 && svgX <= (viewBoxWidth - pad) + 10) {
      state.selectedBucket = state.selectedBucket === closestPoint.key ? "" : closestPoint.key;
      render();
    }
  }
});

document.addEventListener("click", (event) => {
  if (!state.selectedBucket) return;

  const isInsideChart = elements.monthlyChart.contains(event.target);
  const isInsideFilterControl =
    (elements.search && elements.search.contains(event.target)) ||
    (elements.partyFilter && elements.partyFilter.contains(event.target)) ||
    (elements.regionFilter && elements.regionFilter.contains(event.target)) ||
    (elements.answerFilter && elements.answerFilter.contains(event.target)) ||
    (elements.searchQuestionOnly && elements.searchQuestionOnly.contains(event.target)) ||
    (elements.resetFilters && elements.resetFilters.contains(event.target));

  // The row menu, the similar-questions panel and the answer popup are their own UI, not
  // a click away from the chart — copying an answer shouldn't drop the selected month.
  if (
    event.target.closest("[data-row-menu]") ||
    event.target.closest("#similar-panel") ||
    event.target.closest("#answer-tooltip")
  ) {
    return;
  }

  const isClearLink =
    event.target.id === "clear-bucket-filter" ||
    event.target.id === "clear-topic-filter" ||
    event.target.id === "clear-filters-link";

  if (isInsideChart || isInsideFilterControl || isClearLink) {
    return;
  }

  state.selectedBucket = "";
  render();
});

let resizeTimeout;
window.addEventListener("resize", () => {
  cancelAnimationFrame(resizeTimeout);
  resizeTimeout = requestAnimationFrame(() => {
    render();
  });
});

// Apply the vertical's branding so a new version only needs config.js edits.
function applyVerticalBranding() {
  document.title = VERTICAL.brandTitle;
  const brand = document.querySelector(".brand");
  if (brand) brand.textContent = VERTICAL.brandTitle;
  const totalLabel = document.querySelector("#metric-total-label");
  if (totalLabel) totalLabel.textContent = `Total ${VERTICAL.topic} PQs`;
}
applyVerticalBranding();

loadData()
  .then(() => {
    if (elements.searchQuestionOnly) {
      elements.searchQuestionOnly.checked = state.searchQuestionOnly;
    }

    renderSelects();
    render();

  })
  .catch((error) => {
    console.error(error);
    elements.status.textContent = "Could not load dashboard data from this repo.";
  });


