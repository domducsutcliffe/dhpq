#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { pbkdf2Sync, createDecipheriv } from "node:crypto";
import { gunzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getVertical, DEFAULT_VERTICAL_ID } from "../config.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const dataDir = path.join(repoRoot, "data");

// Which vertical are we building? `node refresh-data.mjs --vertical=<id>`
// (defaults to DEFAULT_VERTICAL_ID). Per-vertical outputs live in data/<id>/;
// geography files (constituency-*) are shared at data/.
const verticalArg = process.argv.find((a) => a.startsWith("--vertical="));
const VERTICAL = getVertical(verticalArg ? verticalArg.split("=")[1] : DEFAULT_VERTICAL_ID);
const verticalDir = path.join(dataDir, VERTICAL.id);
console.log(
  `Building vertical "${VERTICAL.id}" (searchTerm: ${VERTICAL.searchTerm ?? "none — department-wide"})`,
);

const QUESTIONS_ENDPOINT =
  "https://questions-statements-api.parliament.uk/api/writtenquestions/questions";
const DETAIL_BASE = "https://questions-statements.parliament.uk/written-questions/detail";
const CONSTITUENCY_CSV =
  "https://pages.mysociety.org/2025-constituencies/data/parliament_con_2025/latest/parl_constituencies_2025.csv";
const CONSTITUENCY_2020_CSV =
  "https://open-geography-portalx-ons.hub.arcgis.com/api/download/v1/items/0dbc00e2529e42b1807e04ddb1da6df5/csv?layers=0";
const PARL10_TO_PARL25_CSV =
  "https://pages.mysociety.org/2025-constituencies/data/geographic_overlaps/latest/PARL10_PARL25_combo_overlap.csv";
const TOPIC_TAXONOMY_PATH = path.join(verticalDir, "topic-taxonomy.json");

const PAGE_SIZE = Number(process.env.PAGE_SIZE || 100);
const LIST_DELAY_MS = Number(process.env.LIST_DELAY_MS || 150);

// How far back the window reaches. Either an absolute start date (WINDOW_START /
// vertical.windowStart — e.g. the first sitting day of this Parliament) or a rolling
// LOOKBACK_DAYS back from today. Everything outside it is dropped on every refresh.
const LOOKBACK_DAYS = Number(process.env.LOOKBACK_DAYS || VERTICAL.lookbackDays || 0);
const WINDOW_START = process.env.WINDOW_START || VERTICAL.windowStart || "";

// A vertical may declare a single searchTerm, a list of them, or null. The API's
// searchTerm parameter only takes one term (with an optional trailing wildcard), so
// for multi-term verticals we run one paged fetch per term and merge by question id.
// null means no keyword scope at all: fetch everything the department answers.
const SEARCH_TERMS = VERTICAL.searchTerm
  ? (Array.isArray(VERTICAL.searchTerm) ? VERTICAL.searchTerm : [VERTICAL.searchTerm])
  : [];

const SOURCE_PARAMS = {
  house: VERTICAL.house,
  answeringBodies: VERTICAL.answeringBodies,
  answered: "Any",
  includeWithdrawn: "false",
  expandMember: "true",
  // Provenance only — every real request overrides this per term in fetchForTerms().
  ...(SEARCH_TERMS.length ? { searchTerm: SEARCH_TERMS.join(" | ") } : {}),
};

// Word-boundary, case-insensitive regex built from the vertical's match roots, used to
// keep only questions whose heading or text actually mentions the topic. A vertical with
// no match roots (this one) is department-wide: every question the API returns is in scope.
const VERTICAL_MATCH = VERTICAL.matchRoots.length
  ? new RegExp(`\\b(${VERTICAL.matchRoots.join("|")})`, "i")
  : null;

function matchesVertical(q) {
  if (!VERTICAL_MATCH) return true;
  return VERTICAL_MATCH.test(q.heading || "") || VERTICAL_MATCH.test(q.questionText || "");
}

const NHS_REGION_BY_PARLIAMENT_REGION = new Map([
  ["eastern", "East of England"],
  ["east of england", "East of England"],
  ["london", "London"],
  ["north east", "North East and Yorkshire"],
  ["yorkshire and the humber", "North East and Yorkshire"],
  ["yorkshire and the humber region", "North East and Yorkshire"],
  ["north west", "North West"],
  ["east midlands", "Midlands"],
  ["west midlands", "Midlands"],
  ["south east", "South East"],
  ["south west", "South West"],
]);

const DEVOLVED_NATIONS = new Set(["Scotland", "Wales", "Northern Ireland"]);
const STOPWORDS = new Set([
  "a", "an", "and", "any", "are", "as", "at", "be", "been", "being", "by", "for", "from", "has",
  "have", "how", "in", "into", "is", "it", "its", "of", "on", "or", "that", "the", "their", "them",
  "there", "these", "this", "those", "to", "was", "were", "what", "when", "where", "which", "who",
  "why", "will", "with", "would", "could", "should", "department", "health", "social", "care",
  "asked", "ask", "minister", "state", "secretary", "whether", "if", "made", "make", "plans",
  "plan", "number", "many",
]);
const TOPIC_WINDOW_MONTHS = 6;
const TOPIC_MIN_COUNT = 3;
const TOPIC_LIMIT = 8;
const POLICY_TERMS = [
  "nhs",
  "contract",
  "uda",
  "workforce",
  "recruit",
  "retain",
  "waiting",
  "access",
  "appointment",
  "charge",
  "afford",
  "fluor",
  "prevention",
  "oral health",
  "children",
  "commission",
  "icb",
  "covid",
  "pandemic",
  "training",
  "education",
  "dent",
];

function simpleHash(value) {
  let hash = 2166136261;
  const text = String(value || "");
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function toTopicText(question) {
  return `${question.heading || ""} ${question.questionText || ""}`.toLowerCase();
}

function normaliseTopicToken(token) {
  return token.replace(/[^a-z0-9-]+/g, "").replace(/^-+|-+$/g, "");
}

function extractTopicPhrases(text) {
  const rawTokens = text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]+/g, " ")
    .split(/\s+/)
    .map(normaliseTopicToken)
    .filter(Boolean);

  const tokens = rawTokens.filter(
    (token) => token.length >= 3 && !STOPWORDS.has(token) && !/^\d+$/.test(token),
  );
  const phrases = new Set();
  for (let i = 0; i < tokens.length; i += 1) {
    const one = tokens[i];
    if (!STOPWORDS.has(one)) phrases.add(one);
    if (i + 1 < tokens.length) {
      const two = `${tokens[i]} ${tokens[i + 1]}`;
      if (!STOPWORDS.has(tokens[i]) && !STOPWORDS.has(tokens[i + 1])) phrases.add(two);
    }
    if (i + 2 < tokens.length) {
      const three = `${tokens[i]} ${tokens[i + 1]} ${tokens[i + 2]}`;
      if (!STOPWORDS.has(tokens[i]) && !STOPWORDS.has(tokens[i + 1]) && !STOPWORDS.has(tokens[i + 2])) {
        phrases.add(three);
      }
    }
  }
  return [...phrases];
}

function normaliseForMatch(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function titleCase(value) {
  return String(value || "")
    .split(" ")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

async function loadTopicTaxonomy() {
  let raw;
  try {
    raw = await readFile(TOPIC_TAXONOMY_PATH, "utf8");
  } catch {
    // A new vertical may not have a curated taxonomy yet — degrade gracefully so the
    // dashboard still builds (every question simply falls under "General").
    console.log(`No topic taxonomy at ${TOPIC_TAXONOMY_PATH}; using empty taxonomy.`);
    return { version: "none", concepts: [] };
  }
  const parsed = JSON.parse(raw);
  const concepts = (parsed.concepts || []).map((concept) => ({
    label: concept.label,
    aliases: (concept.aliases || []).map(normaliseForMatch).filter(Boolean),
  }));
  return {
    version: parsed.version || "unknown",
    concepts,
  };
}

function matchQuestionConcepts(normalisedText, taxonomy) {
  const hits = [];
  for (const concept of taxonomy.concepts) {
    if (concept.aliases.some((alias) => alias && normalisedText.includes(alias))) {
      hits.push(concept.label);
    }
  }
  return hits;
}

function buildMonthFingerprint(monthQuestions) {
  const canonical = monthQuestions
    .map((q) => `${q.id}|${q.uin}|${q.dateTabled}|${simpleHash(toTopicText(q))}`)
    .sort()
    .join("||");
  return simpleHash(canonical);
}

function previousMonths(month, orderedMonths, count) {
  const idx = orderedMonths.indexOf(month);
  if (idx <= 0) return [];
  return orderedMonths.slice(Math.max(0, idx - count), idx);
}

function computeMonthlyTopics(month, monthConceptCounts, monthTotals, orderedMonths) {
  const conceptCounts = monthConceptCounts.get(month) || new Map();
  const monthTotal = monthTotals.get(month) || 1;
  const trailingMonths = previousMonths(month, orderedMonths, TOPIC_WINDOW_MONTHS);

  const rows = [];
  for (const [label, count] of conceptCounts.entries()) {
    if (count < TOPIC_MIN_COUNT) continue;
    const volumeScore = count / monthTotal;

    let baselineAvg = 0;
    if (trailingMonths.length) {
      const trailingCounts = trailingMonths.map((m) => monthConceptCounts.get(m)?.get(label) || 0);
      baselineAvg = trailingCounts.reduce((sum, value) => sum + value, 0) / trailingCounts.length;
    }
    const spikeScore = (count + 1) / (baselineAvg + 1);
    const score = volumeScore * 0.6 + Math.log1p(spikeScore) * 0.4;

    rows.push({
      label,
      count,
      score: Number(score.toFixed(6)),
      volumeScore: Number(volumeScore.toFixed(6)),
      spikeScore: Number(spikeScore.toFixed(6)),
    });
  }

  return rows
    .sort((a, b) => b.score - a.score || b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, TOPIC_LIMIT);
}

// Decrypt an AES-256-GCM container produced by scripts/encrypt-data.mjs. The current
// format is binary ("PQE1" magic + iterations + salt/iv/tag + ciphertext); a legacy
// base64 JSON envelope is still accepted so a refresh can read a `.enc` written before
// the format change. Mirrors the browser's decrypt.
function decryptContainer(buf, password) {
  const magic = buf.length >= 52 ? buf.toString("ascii", 0, 4) : "";
  if (magic === "PQE1" || magic === "PQE2") {
    const iterations = buf.readUInt32LE(4);
    const salt = buf.subarray(8, 24);
    const iv = buf.subarray(24, 36);
    const tag = buf.subarray(36, 52);
    const data = buf.subarray(52);
    const key = pbkdf2Sync(password, salt, iterations, 32, "sha256");
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(data), decipher.final()]);
    return (magic === "PQE2" ? gunzipSync(plain) : plain).toString("utf8");
  }
  // Legacy base64 JSON envelope.
  const env = JSON.parse(buf.toString("utf8"));
  const salt = Buffer.from(env.salt, "base64");
  const iv = Buffer.from(env.iv, "base64");
  const tag = Buffer.from(env.tag, "base64");
  const data = Buffer.from(env.data, "base64");
  const key = pbkdf2Sync(password, salt, env.iterations || 100_000, 32, "sha256");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

// Read a vertical data file as text: prefer committed plaintext (local dev), else
// fall back to decrypting the committed `.enc` with PQ_PASSWORD. On CI only the
// encrypted files are committed, so without this the refresh can't see its own
// prior output and re-does a full fetch + full answer enrichment every run.
async function readVerticalJson(name) {
  try {
    return await readFile(path.join(verticalDir, name), "utf8");
  } catch {
    // no plaintext — try the encrypted sibling
  }
  const password = process.env.PQ_PASSWORD;
  if (!password) return null;
  try {
    const encBuf = await readFile(path.join(verticalDir, `${name}.enc`)); // raw bytes
    return decryptContainer(encBuf, password);
  } catch (error) {
    console.warn(`Could not read ${name} (plaintext or .enc): ${error.message}`);
    return null;
  }
}

async function loadPreviousSummary() {
  try {
    const payload = await readVerticalJson("summary.json");
    return payload ? JSON.parse(payload) : null;
  } catch {
    return null;
  }
}

function normaliseName(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/&/g, " and ")
    .replace(/[^a-zA-Z0-9]+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

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

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];

    if (quoted) {
      if (char === '"' && next === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
      continue;
    }

    if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else if (char !== "\r") {
      cell += char;
    }
  }

  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }

  const [headers, ...dataRows] = rows;
  return dataRows
    .filter((cells) => cells.length && cells.some(Boolean))
    .map((cells) =>
      Object.fromEntries(headers.map((header, index) => [header, cells[index] || ""])),
    );
}

async function fetchJson(url, tries = 5) {
  let lastError;
  for (let attempt = 1; attempt <= tries; attempt += 1) {
    try {
      // Without a timeout a stalled socket hangs this await forever and the retry
      // logic below never runs — a long backfill can silently wedge on one bad
      // connection. Abort slow requests so they fall through to a retry instead.
      const response = await fetch(url, { signal: AbortSignal.timeout(20000) });
      if (!response.ok) {
        const error = new Error(`${response.status} ${response.statusText}`);
        error.status = response.status;
        error.retryAfterMs = (Number(response.headers.get("retry-after")) || 0) * 1000;
        throw error;
      }
      return await response.json();
    } catch (error) {
      lastError = error;
      if (attempt < tries) {
        // 429 (rate limited) needs a much longer backoff than transient errors
        const base = error.status === 429 ? 3000 : 800;
        const wait = error.retryAfterMs || base * attempt;
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
    }
  }
  throw lastError;
}

async function fetchText(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText} from ${url}`);
  }
  return response.text();
}

// Reassemble the chunked encrypted questions (questions-0.json.enc, …) using the
// unencrypted questions-index.json manifest. This is the only form committed to the
// repo — the plaintext is gitignored and encrypt-data.mjs deletes the single
// questions.json.enc — so without this a CI run finds no previous data at all and
// silently discards every full-text repair from earlier runs.
async function loadChunkedQuestions() {
  const password = process.env.PQ_PASSWORD;
  if (!password) return null;
  let index;
  try {
    index = JSON.parse(await readFile(path.join(verticalDir, "questions-index.json"), "utf8"));
  } catch {
    return null;
  }
  const chunks = Number(index.chunks || 0);
  if (!chunks) return null;
  const all = [];
  for (let i = 0; i < chunks; i += 1) {
    try {
      const buf = await readFile(path.join(verticalDir, `questions-${i}.json.enc`));
      const parsed = JSON.parse(decryptContainer(buf, password));
      all.push(...(parsed.questions || parsed || []));
    } catch (error) {
      console.warn(`Could not read questions chunk ${i}: ${error.message}`);
      return null; // a partial read would look like deleted questions — safer to bail
    }
  }
  return all;
}

async function loadPreviousQuestions() {
  try {
    const raw = await readVerticalJson("questions.json");
    if (raw) return JSON.parse(raw).questions || [];
  } catch {
    // fall through to the chunked form
  }
  const chunked = await loadChunkedQuestions();
  if (chunked) {
    console.log(`Loaded ${chunked.length.toLocaleString()} previous questions from encrypted chunks.`);
    return chunked;
  }
  return [];
}

function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

// Never look back further than the configured window start.
function maxDate(a, b) {
  return a > b ? a : b;
}

function subtractDays(dateStr, days) {
  const date = new Date(dateStr);
  date.setDate(date.getDate() - days);
  return date.toISOString().slice(0, 10);
}

// The first date in scope: an absolute window start wins, otherwise roll back from today.
function getWindowStart() {
  if (WINDOW_START) return WINDOW_START;
  if (LOOKBACK_DAYS > 0) return subtractDays(todayIso(), LOOKBACK_DAYS);
  throw new Error("No window configured: set windowStart or lookbackDays in config.js.");
}

// A freshly mapped question only carries the list endpoint's truncated answerText and
// 255-char questionText (no answerFull/questionFull). If the previous run already
// enriched that same question from the detail endpoint, carry the full text forward so
// we don't re-fetch the whole window's details every refresh. The truncated snippet is
// a prefix of the full text, so a prefix match means it's unchanged; a mismatch (an
// amended answer) correctly falls through to re-enrichment.
function carryForwardFullText(question, prior) {
  if (!prior) return;
  if (prior.answerFull && !question.answerFull && prior.answerText) {
    const snippet = (question.answerText || "").replace(/\.\.\.$/, "");
    if (snippet && prior.answerText.startsWith(snippet)) {
      question.answerText = prior.answerText;
      question.answerFull = true;
    }
  }
  if (prior.questionFull && !question.questionFull && prior.questionText) {
    const snippet = question.questionText || "";
    if (snippet && prior.questionText.startsWith(snippet)) {
      question.questionText = prior.questionText;
      question.questionFull = true;
    }
  }
}

async function fetchQuestionsPaged(queryParams) {
  const all = [];
  let total = null;

  for (let skip = 0; total === null || skip < total; skip += PAGE_SIZE) {
    const params = new URLSearchParams({
      ...SOURCE_PARAMS,
      ...queryParams,
      take: String(PAGE_SIZE),
      skip: String(skip),
    });
    const url = `${QUESTIONS_ENDPOINT}?${params}`;
    const payload = await fetchJson(url);
    const pageItems = payload.results || [];

    total = Number(payload.totalResults || pageItems.length || 0);
    all.push(...pageItems);

    if (!pageItems.length) {
      break;
    }
    if (LIST_DELAY_MS) {
      await new Promise((resolve) => setTimeout(resolve, LIST_DELAY_MS));
    }
  }

  return all;
}

// Calendar-month [from, to] ranges covering start..end inclusive.
function monthChunks(start, end) {
  const chunks = [];
  const cursor = new Date(`${start.slice(0, 7)}-01T00:00:00Z`);
  const last = new Date(`${end}T00:00:00Z`);
  while (cursor <= last) {
    const monthStart = cursor.toISOString().slice(0, 10);
    const monthEnd = new Date(
      Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 0),
    )
      .toISOString()
      .slice(0, 10);
    chunks.push({
      tabledWhenFrom: monthStart < start ? start : monthStart,
      tabledWhenTo: monthEnd > end ? end : monthEnd,
    });
    cursor.setUTCMonth(cursor.getUTCMonth() + 1);
  }
  return chunks;
}

// Fetch the window one calendar month at a time.
//
// Not just politeness: asking for the whole Parliament in one paged query means skip
// values marching up to 22,000, and the API starts resetting the connection long before
// that (a request that returns in 5s at skip=0 simply dies deep in). A month of
// questions is ~300 rows — three or four shallow pages — which it serves happily.
async function fetchWindow(windowStart, windowEnd) {
  const chunks = monthChunks(windowStart, windowEnd);
  const byId = new Map();

  for (const [index, chunk] of chunks.entries()) {
    const items = await fetchForTerms(chunk);
    for (const item of items) {
      const q = getQuestion(item);
      if (q && q.id != null) byId.set(q.id, item);
    }
    console.log(
      `  [${index + 1}/${chunks.length}] ${chunk.tabledWhenFrom} → ${chunk.tabledWhenTo}: ` +
        `${items.length} questions (${byId.size.toLocaleString()} total)`,
    );
  }

  return [...byId.values()];
}

// Run the paged fetch once per configured search term and merge the raw items by
// question id (a question matching two of the configured terms is fetched by each of
// them, but must appear only once).
async function fetchForTerms(queryParams) {
  // Department-wide: no searchTerm parameter at all.
  if (!SEARCH_TERMS.length) {
    return fetchQuestionsPaged(queryParams);
  }
  if (SEARCH_TERMS.length === 1) {
    return fetchQuestionsPaged({ ...queryParams, searchTerm: SEARCH_TERMS[0] });
  }

  const byId = new Map();
  let succeeded = 0;
  for (const term of SEARCH_TERMS) {
    console.log(`— searchTerm "${term}"`);
    try {
      const items = await fetchQuestionsPaged({ ...queryParams, searchTerm: term });
      for (const item of items) {
        const q = getQuestion(item);
        if (q && q.id != null) byId.set(q.id, item);
      }
      succeeded += 1;
    } catch (error) {
      // One term failing (e.g. a transient 429/500) shouldn't sink the whole build —
      // keep what the other terms returned. If every term fails, re-throw so the run
      // doesn't silently overwrite the dataset with nothing.
      console.warn(`  searchTerm "${term}" failed: ${error.message} — skipping this term.`);
    }
  }
  if (!succeeded) {
    throw new Error(`All ${SEARCH_TERMS.length} search terms failed; aborting to preserve existing data.`);
  }
  console.log(`Merged ${byId.size} unique questions across ${succeeded}/${SEARCH_TERMS.length} search terms`);
  return [...byId.values()];
}

function getQuestion(item) {
  return item.value || item;
}

// The list endpoint truncates answerText to ~258 chars (ending in "...") and
// questionText to a hard 255-char cap. The full text is only available from the
// per-question detail endpoint, so we fetch it for rows that still look truncated.
function needsFullAnswer(q) {
  if (!q.answered || !q.id || q.answerFull) return false;
  const text = q.answerText || "";
  return !text || text.length >= 255 || /\.\.\.$/.test(text);
}

// A complete question always ends in sentence punctuation. The list endpoint caps
// questionText at 255 chars (254 once stripHtml trims a trailing space), so the old
// `length >= 255` test missed the trimmed ones entirely. Detect truncation by the
// missing full stop instead — immune to off-by-ones, and it catches any future case.
function needsFullQuestion(q) {
  if (!q.id || q.questionFull) return false;
  const text = (q.questionText || "").trim();
  if (!text) return false;
  return !/[.?!]["')\]]*$/.test(text);
}

async function writeQuestions(questions) {
  await writeFile(
    path.join(verticalDir, "questions.json"),
    `${JSON.stringify({ questions })}\n`,
    "utf8",
  );
}

async function enrichFullAnswers(questions) {
  // Truncated questions are always worth fetching (question text is the primary content
  // in the table). Answers are only targeted when this vertical actually stores them.
  const outstanding = questions.filter(
    (q) => (VERTICAL.enrichAnswers && needsFullAnswer(q)) || needsFullQuestion(q),
  );
  if (!outstanding.length) {
    console.log("Nothing needs full-text enrichment.");
    return;
  }

  // Cap the work per run. A few thousand detail calls in one go trips Cloudflare's bot
  // challenge (HTTP 429 "Just a moment" pages), which wedges the whole refresh. Repair a
  // slice each run instead and let the backlog heal over successive runs — newest first,
  // since those are what the table shows. Anything still outstanding renders with a
  // "…" and a link to the full text on parliament.uk, so it never looks silently cut off.
  const maxPerRun = Number(process.env.ENRICH_MAX_PER_RUN || VERTICAL.enrichMaxPerRun || 300);
  outstanding.sort((a, b) => String(b.dateTabled || "").localeCompare(String(a.dateTabled || "")));
  const targets = outstanding.slice(0, maxPerRun);
  if (outstanding.length > targets.length) {
    console.log(
      `${outstanding.length.toLocaleString()} questions need full text; repairing the newest ${targets.length} this run (the rest heal on later runs).`,
    );
  }

  const concurrency = Number(process.env.ANSWER_CONCURRENCY || 8);
  const delayMs = Number(process.env.ANSWER_DELAY_MS || 0);
  // A whole-Parliament backfill is ~22,000 detail calls at a deliberately slow pace, so
  // it runs for hours. Checkpoint questions.json as it goes: if the run dies (rate limit,
  // laptop sleep, Ctrl-C), everything already enriched is on disk and re-running only
  // picks up what is still marked truncated.
  const checkpointEvery = Number(process.env.ANSWER_CHECKPOINT || 250);
  console.log(
    `Fetching full answer text for ${targets.length.toLocaleString()} answered questions (concurrency ${concurrency}, delay ${delayMs}ms)...`,
  );

  let cursor = 0;
  let done = 0;
  let failed = 0;

  async function worker() {
    while (cursor < targets.length) {
      const q = targets[cursor];
      cursor += 1;
      try {
        const payload = await fetchJson(`${QUESTIONS_ENDPOINT}/${q.id}`);
        const detail = getQuestion(payload);
        const fullQuestion = stripHtml(detail.questionText);
        if (fullQuestion) {
          q.questionText = fullQuestion;
        }
        q.questionFull = true;
        // Only store answers when this vertical ships them. Otherwise a question-only
        // backfill would quietly pull ~22,000 answers into the payload — exactly what
        // config.enrichAnswers=false exists to avoid (the app fetches them on hover).
        if (VERTICAL.enrichAnswers) {
          const fullAnswer = stripHtml(detail.answerText);
          if (fullAnswer) {
            q.answerText = fullAnswer;
          }
          // Mark answers as fetched regardless of whether text came back — some
          // answered questions have no inline answer (holding answers, attachment-only),
          // and without this they would be re-fetched on every run forever. Only mark
          // answered rows, so a question answered later still gets its answer fetched.
          if (q.answered) {
            q.answerFull = true;
          }
        }
      } catch {
        failed += 1;
      }
      done += 1;
      if (done % checkpointEvery === 0 || done === targets.length) {
        console.log(
          `  ...full answers ${done}/${targets.length} (${failed} failed) — checkpointing`,
        );
        await writeQuestions(questions);
      }
      if (delayMs) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
  console.log(
    `Full answer enrichment complete: ${done - failed} updated, ${failed} failed.`,
  );
}

async function buildConstituencyLookup() {
  const cachePath = path.join(dataDir, "constituency-lookup-cache.json");
  const forceRebuild = process.argv.includes("--force");

  try {
    if (!forceRebuild) {
      const cacheRaw = await readFile(cachePath, "utf8");
      const cacheParsed = JSON.parse(cacheRaw);
      const lookupMap = new Map(Object.entries(cacheParsed.lookup));
      console.log(`Loaded ${cacheParsed.records.length} constituency mapping records from cache`);
      return { lookup: lookupMap, records: cacheParsed.records };
    }
  } catch (err) {
    console.log("Could not load constituency cache, rebuilding from CSVs...", err.message);
  }

  console.log("Fetching constituency CSVs from external sources...");
  const [csv2025, csv2020, overlapCsv] = await Promise.all([
    fetchText(CONSTITUENCY_CSV),
    fetchText(CONSTITUENCY_2020_CSV),
    fetchText(PARL10_TO_PARL25_CSV),
  ]);
  const rows = parseCsv(csv2025);
  const lookup = new Map();
  const byShortCode = new Map();
  const records = [];

  for (const row of rows) {
    const nation = row.nation || "Unknown";
    const region = row.region || "";
    const nhsRegion = DEVOLVED_NATIONS.has(nation)
      ? nation
      : NHS_REGION_BY_PARLIAMENT_REGION.get(normaliseName(region)) || "Unknown";
    const record = {
      name: row.name,
      shortCode: row.short_code,
      gssCode: row.gss_code,
      nation,
      parliamentaryRegion: region,
      nhsRegion,
      sourceBoundary: "2024",
    };

    records.push(record);
    byShortCode.set(row.short_code, record);
    lookup.set(normaliseName(row.name), record);
  }

  const overlapBy2010Code = new Map();
  for (const row of parseCsv(overlapCsv)) {
    const current = overlapBy2010Code.get(row.PARL10);
    const overlap = Number(row.percentage_overlap_pop || row.percentage_overlap_area || 0);
    if (!current || overlap > current.overlap) {
      overlapBy2010Code.set(row.PARL10, {
        targetCode: row.PARL25,
        overlap,
      });
    }
  }

  for (const row of parseCsv(csv2020)) {
    const name = row.PCON20NM;
    const target = overlapBy2010Code.get(row.PCON20CD);
    const mapped = target ? byShortCode.get(target.targetCode) : null;
    if (!name || !mapped) continue;

    lookup.set(normaliseName(name), {
      name,
      shortCode: row.PCON20CD,
      gssCode: row.PCON20CD,
      nation: mapped.nation,
      parliamentaryRegion: mapped.parliamentaryRegion,
      nhsRegion: mapped.nhsRegion,
      sourceBoundary: "2010 mapped to 2024",
      mappedToConstituency: mapped.name,
      mappedToShortCode: mapped.shortCode,
      overlap: target.overlap,
    });
  }

  // Save cache to disk
  try {
    await writeFile(
      cachePath,
      JSON.stringify({
        records,
        lookup: Object.fromEntries(lookup.entries())
      }, null, 2) + "\n",
      "utf8"
    );
    console.log("Saved constituency lookup cache to data/constituency-lookup-cache.json");
  } catch (err) {
    console.warn("Could not save constituency lookup cache:", err.message);
  }

  return { lookup, records };
}


function mapQuestion(item, constituencyLookup) {
  const q = getQuestion(item);
  const member = q.askingMember || {};
  const constituency = member.memberFrom || "";
  const regionRecord = constituencyLookup.get(normaliseName(constituency));
  const dateTabled = q.dateTabled ? q.dateTabled.slice(0, 10) : "";
  const dateAnswered = q.dateAnswered ? q.dateAnswered.slice(0, 10) : "";

  return {
    id: q.id,
    uin: q.uin,
    url: dateTabled && q.uin ? `${DETAIL_BASE}/${dateTabled}/${q.uin}` : "",
    heading: q.heading || "",
    questionText: stripHtml(q.questionText),
    answerText: stripHtml(q.answerText),
    dateTabled,
    dateAnswered,
    dateForAnswer: q.dateForAnswer ? q.dateForAnswer.slice(0, 10) : "",
    answered: Boolean(dateAnswered),
    answeringBodyName: q.answeringBodyName || "",
    isNamedDay: Boolean(q.isNamedDay),
    member: {
      id: member.id || null,
      name: member.name || "",
      party: member.party || "",
      partyAbbreviation: member.partyAbbreviation || "",
      constituency,
    },
    region: {
      constituency,
      nation: regionRecord?.nation || "Unknown",
      parliamentaryRegion: regionRecord?.parliamentaryRegion || "",
      nhsRegion: regionRecord?.nhsRegion || "Unknown",
      sourceBoundary: regionRecord?.sourceBoundary || "unmatched",
      mappedToConstituency: regionRecord?.mappedToConstituency || "",
    },
  };
}

function increment(map, key, amount = 1) {
  const cleanKey = key || "Unknown";
  map.set(cleanKey, (map.get(cleanKey) || 0) + amount);
}

function sortedCounts(map) {
  return [...map.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function buildSummary(
  questions,
  constituencyRecords,
  unmatchedConstituencies,
  taxonomy,
  previousSummary = null,
) {
  const partyCounts = new Map();
  const partyNames = new Map();
  const regionCounts = new Map();
  const memberCounts = new Map();
  const monthly = new Map();
  const monthQuestions = new Map();
  const monthConceptCounts = new Map();
  let answered = 0;

  for (const question of questions) {
    if (question.answered) answered += 1;

    const partyKey = question.member.partyAbbreviation || question.member.party || "Unknown";
    increment(partyCounts, partyKey);
    if (question.member.party) partyNames.set(partyKey, question.member.party);
    increment(regionCounts, question.region.nhsRegion);
    increment(memberCounts, question.member.name || "Unknown");

    const month = question.dateTabled ? question.dateTabled.slice(0, 7) : "Unknown";
    if (!monthly.has(month)) {
      monthly.set(month, {
        month,
        total: 0,
        answered: 0,
        unanswered: 0,
        byParty: {},
        byRegion: {},
      });
    }
    if (!monthQuestions.has(month)) monthQuestions.set(month, []);
    monthQuestions.get(month).push(question);
    const bucket = monthly.get(month);
    bucket.total += 1;
    bucket[question.answered ? "answered" : "unanswered"] += 1;
    bucket.byParty[partyKey] = (bucket.byParty[partyKey] || 0) + 1;
    bucket.byRegion[question.region.nhsRegion] =
      (bucket.byRegion[question.region.nhsRegion] || 0) + 1;
  }

  const dates = questions.map((question) => question.dateTabled).filter(Boolean).sort();
  const parties = sortedCounts(partyCounts).map((party) => ({
    ...party,
    name: partyNames.get(party.key) || party.key,
  }));
  const sortedMonthlyRows = [...monthly.values()].sort((a, b) => a.month.localeCompare(b.month));
  const orderedMonths = sortedMonthlyRows.map((m) => m.month);

  for (const month of orderedMonths) {
    const counts = new Map();
    for (const q of monthQuestions.get(month) || []) {
      if (q.topic && q.topic !== "General") {
        counts.set(q.topic, (counts.get(q.topic) || 0) + 1);
      }
    }
    monthConceptCounts.set(month, counts);
  }

  const prevTopics = previousSummary?.topics || {};
  const prevFingerprints = prevTopics.monthFingerprints || {};
  const prevByMonth = prevTopics.byMonth || {};
  const prevMethodMatches =
    prevTopics.method === "taxonomy-plus-trends" && prevTopics.taxonomyVersion === taxonomy.version;
  const monthFingerprints = {};
  const byMonth = {};
  const monthTotals = new Map(sortedMonthlyRows.map((row) => [row.month, row.total]));

  for (const month of orderedMonths) {
    const fingerprint = buildMonthFingerprint(monthQuestions.get(month) || []);
    monthFingerprints[month] = fingerprint;
    const unchanged = prevMethodMatches && prevFingerprints[month] && prevFingerprints[month] === fingerprint;
    const previousRows = prevByMonth[month];
    const previousShapeValid =
      Array.isArray(previousRows) && previousRows.every((row) => typeof row?.label === "string");
    if (unchanged && previousShapeValid) {
      byMonth[month] = prevByMonth[month];
      continue;
    }
    byMonth[month] = computeMonthlyTopics(month, monthConceptCounts, monthTotals, orderedMonths);
  }

  return {
    generatedAt: new Date().toISOString(),
    source: {
      questionsEndpoint: QUESTIONS_ENDPOINT,
      constituencySource: CONSTITUENCY_CSV,
      historicConstituencySource: CONSTITUENCY_2020_CSV,
      constituencyOverlapSource: PARL10_TO_PARL25_CSV,
      params: SOURCE_PARAMS,
    },
    window: {
      startsOn: getWindowStart(),
      lookbackDays: WINDOW_START ? null : LOOKBACK_DAYS,
      builtOn: todayIso(),
    },
    totals: {
      questions: questions.length,
      answered,
      unanswered: questions.length - answered,
      unheaded: questions.filter((question) => question.topic === UNHEADED_TOPIC).length,
      constituenciesInLookup: constituencyRecords.length,
      unmatchedConstituencies: unmatchedConstituencies.length,
    },
    dateRange: {
      oldestTabled: dates[0] || "",
      newestTabled: dates.at(-1) || "",
    },
    parties,
    regions: sortedCounts(regionCounts),
    topMembers: sortedCounts(memberCounts).slice(0, 20),
    monthly: sortedMonthlyRows,
    topics: {
      method: "taxonomy-plus-trends",
      taxonomyVersion: taxonomy.version,
      generatedAt: new Date().toISOString(),
      monthFingerprints,
      byMonth,
    },
    unmatchedConstituencies,
  };
}

// Department-wide topics come straight from Parliament's own heading convention:
// every heading is "Subject" or "Subject: Qualifier" ("Dental Services",
// "GP Practice Lists: Registration"), so the text before the colon is already a
// clean, exhaustive subject taxonomy — no curated concept list to maintain, and no
// TF-IDF classifier that only knows about one specialism.
//
// The catch, and it bites hardest on exactly this "past week" window: Parliament
// assigns the heading late, around the time the question is answered. The freshest
// couple of days are therefore unheaded, and they are called that rather than being
// quietly filed under a real subject. Each refresh re-fetches the whole window, so a
// question picks up its true subject here as soon as Parliament publishes it.
const UNHEADED_TOPIC = "Awaiting heading";

function classifyByHeading(questions) {
  for (const question of questions) {
    const subject = String(question.heading || "").split(":")[0].trim();
    question.topic = subject || UNHEADED_TOPIC;
  }
}

function classifyQuestions(questions, taxonomy) {
  const tokenize = (text) => {
    return String(text || "")
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .map((w) => w.trim())
      .filter((w) => w.length > 2 && !STOPWORDS.has(w));
  };

  const df = new Map();
  const docTokens = questions.map((q) => {
    const headingTokens = tokenize(q.heading || "");
    const questionTokens = tokenize(q.questionText || "");
    const tokens = [...headingTokens, ...headingTokens, ...questionTokens];
    const uniqueTokens = new Set(tokens);
    for (const token of uniqueTokens) {
      df.set(token, (df.get(token) || 0) + 1);
    }
    return tokens;
  });

  const N = questions.length;
  const getIdf = (token) => {
    const count = df.get(token) || 0;
    if (count === 0) return 0;
    return Math.log(1 + N / count);
  };

  const conceptVectors = taxonomy.concepts.map((concept) => {
    const labelTokens = tokenize(concept.label);
    const aliasTokens = (concept.aliases || []).flatMap((alias) => tokenize(alias));
    const termWeights = new Map();
    for (const t of labelTokens) {
      termWeights.set(t, (termWeights.get(t) || 0) + 3.0);
    }
    for (const t of aliasTokens) {
      termWeights.set(t, (termWeights.get(t) || 0) + 1.0);
    }

    const vector = new Map();
    let magnitudeSq = 0;
    for (const [term, weight] of termWeights.entries()) {
      const idf = getIdf(term);
      if (idf > 0) {
        const val = weight * idf;
        vector.set(term, val);
        magnitudeSq += val * val;
      }
    }

    return {
      label: concept.label,
      vector,
      magnitude: Math.sqrt(magnitudeSq),
    };
  });

  questions.forEach((q, idx) => {
    const tokens = docTokens[idx];
    const tf = new Map();
    for (const token of tokens) {
      tf.set(token, (tf.get(token) || 0) + 1);
    }

    const qVector = new Map();
    let qMagnitudeSq = 0;
    for (const [term, count] of tf.entries()) {
      const idf = getIdf(term);
      if (idf > 0) {
        const val = count * idf;
        qVector.set(term, val);
        qMagnitudeSq += val * val;
      }
    }
    const qMagnitude = Math.sqrt(qMagnitudeSq);

    let bestLabel = "General";
    let bestScore = 0;

    if (qMagnitude > 0) {
      for (const concept of conceptVectors) {
        if (concept.magnitude === 0) continue;
        let dotProduct = 0;
        for (const [term, val] of qVector.entries()) {
          const conceptVal = concept.vector.get(term) || 0;
          dotProduct += val * conceptVal;
        }
        const score = dotProduct / (qMagnitude * concept.magnitude);
        if (score > bestScore) {
          bestScore = score;
          bestLabel = concept.label;
        }
      }
    }

    q.topic = bestScore >= 0.03 ? bestLabel : "General";
  });
}

async function main() {
  await mkdir(dataDir, { recursive: true });
  await mkdir(verticalDir, { recursive: true });

  // --enrich-only: skip the (rate-limit-prone) list fetch and just backfill full
  // answer text into the existing questions.json. Idempotent — only touches answers
  // still marked truncated, so it can be re-run until everything is enriched.
  if (process.argv.includes("--enrich-only")) {
    const existing = await loadPreviousQuestions();
    if (!existing.length) {
      console.log("Enrich-only: no existing questions.json found, nothing to do.");
      return;
    }
    console.log(`Enrich-only mode: loaded ${existing.length.toLocaleString()} questions.`);
    await enrichFullAnswers(existing);
    await writeFile(
      path.join(verticalDir, "questions.json"),
      `${JSON.stringify({ questions: existing })}\n`,
      "utf8",
    );
    console.log("Enrich-only complete: questions.json updated.");
    return;
  }

  const taxonomy = await loadTopicTaxonomy();
  const { lookup, records: constituencyRecords } = await buildConstituencyLookup();

  const existingQuestions = await loadPreviousQuestions();
  const isOffline = process.argv.includes("--offline");
  const skipEnrich = process.argv.includes("--no-enrich");
  const windowStart = getWindowStart();

  // The dataset is the whole window (e.g. this Parliament), but questions older than a
  // month or so are settled — they already have their answer and it won't change. So by
  // default only the recent slice is re-fetched and merged over the carried-forward
  // dataset. Two queries cover the ways a row can change: tabled recently (new questions)
  // and *answered* recently (a question tabled months ago can still be answered late).
  // `--full` forces a complete rebuild of the window.
  const forceFull = process.argv.includes("--full");
  const lookbackDays = Number(process.env.REFRESH_LOOKBACK_DAYS || 60);

  let questions;
  if (isOffline) {
    console.log("Offline mode: rebuilding from existing questions only (no API fetch)...");
    questions = existingQuestions;
  } else if (existingQuestions.length && !forceFull) {
    const since = maxDate(subtractDays(todayIso(), lookbackDays), windowStart);
    console.log(
      `Incremental refresh: re-fetching questions tabled or answered since ${since} ` +
        `(${existingQuestions.length.toLocaleString()} carried forward). Use --full to rebuild the window.`,
    );

    const [tabledRaw, answeredRaw] = [
      await fetchWindow(since, todayIso()),
      await fetchForTerms({ answeredWhenFrom: since }),
    ];

    const fetched = [...tabledRaw, ...answeredRaw]
      .map((item) => mapQuestion(item, lookup))
      .filter(matchesVertical);

    const byId = new Map(existingQuestions.map((q) => [q.id, q]));
    let added = 0;
    for (const q of fetched) {
      const prior = byId.get(q.id);
      carryForwardFullText(q, prior);
      if (!prior) added += 1;
      byId.set(q.id, q);
    }
    questions = [...byId.values()];
    console.log(
      `Refreshed ${fetched.length} recent questions (${added} new). Total: ${questions.length.toLocaleString()}`,
    );
  } else {
    console.log(
      `Fetching every ${VERTICAL.answeringBodyLabel} question tabled since ${windowStart}, month by month...`,
    );
    const rawItems = await fetchWindow(windowStart, todayIso());
    const fetched = rawItems.map((item) => mapQuestion(item, lookup)).filter(matchesVertical);

    const priorById = new Map(existingQuestions.map((q) => [q.id, q]));
    for (const q of fetched) {
      carryForwardFullText(q, priorById.get(q.id));
    }
    questions = fetched;
    console.log(`Fetched ${questions.length} questions in window`);
  }

  // Drop anything that has aged out of the window (a question tabled 8 days ago is no
  // longer "the past week", even though the previous run stored it).
  const beforePrune = questions.length;
  questions = questions.filter((q) => q.dateTabled && q.dateTabled >= windowStart);
  if (beforePrune !== questions.length) {
    console.log(`Pruned ${beforePrune - questions.length} question(s) tabled before ${windowStart}`);
  }

  // Only Written Questions API data (questions-statements-api.parliament.uk) is used.
  questions.sort((a, b) => {
    const dateCompare = b.dateTabled.localeCompare(a.dateTabled);
    if (dateCompare) return dateCompare;
    return String(b.uin || "").localeCompare(String(a.uin || ""));
  });

  // Always repair truncated QUESTION text: the list endpoint caps it at 255 chars and
  // that text is what the table displays. Answers are separate — for this vertical
  // (config.enrichAnswers false) the browser fetches them on hover rather than us
  // shipping 22,000 of them, so enrichFullAnswers only targets questions here.
  const wantEnrich = !isOffline && !skipEnrich;

  if (wantEnrich) {
    await enrichFullAnswers(questions);
  } else if (isOffline) {
    console.log("Offline mode: skipping live enrichment.");
  } else {
    console.log("Skipping full-text enrichment (--skip-enrich).");
  }

  if (VERTICAL.topicSource === "heading") {
    classifyByHeading(questions);
  } else {
    classifyQuestions(questions, taxonomy);
  }

  const unmatchedConstituencies = [
    ...new Set(
      questions
        .filter((question) => question.region.nhsRegion === "Unknown")
        .map((question) => question.member.constituency)
        .filter(Boolean),
    ),
  ].sort();

  const previousSummary = await loadPreviousSummary();
  const summary = buildSummary(
    questions,
    constituencyRecords,
    unmatchedConstituencies,
    taxonomy,
    previousSummary,
  );

  await writeFile(
    path.join(verticalDir, "questions.json"),
    `${JSON.stringify({ questions })}\n`,
    "utf8",
  );
  await writeFile(
    path.join(verticalDir, "summary.json"),
    `${JSON.stringify(summary, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(dataDir, "constituency-regions.json"),
    `${JSON.stringify({ generatedAt: summary.generatedAt, source: CONSTITUENCY_CSV, constituencies: constituencyRecords }, null, 2)}\n`,
    "utf8",
  );

  console.log(
    `Wrote ${questions.length.toLocaleString()} questions, ${summary.dateRange.oldestTabled} to ${summary.dateRange.newestTabled}`,
  );
  if (unmatchedConstituencies.length) {
    console.log(`Unmatched constituencies: ${unmatchedConstituencies.join(", ")}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
