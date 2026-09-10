// ─────────────────────────────────────────────────────────────────────────────
// VERTICAL CONFIG — the single source of truth for what this dashboard tracks.
//
// This build has no keyword scope at all: every written question the answering body
// answers counts,
// so `searchTerm` is null (the API list call simply omits the parameter) and
// `matchRoots` is empty (nothing is filtered out after the fetch).
//
// The trade-off for "all questions" is volume, so the dataset is windowed by date
// tabled: `windowStart` (an absolute date) or `lookbackDays` (a rolling window back
// from today). Each refresh re-fetches the window and drops anything outside it.
//
// The dataset is rebuilt with:  node scripts/refresh-data.mjs
// (per-vertical output lives in data/<id>/; geography files are shared at data/)
// ─────────────────────────────────────────────────────────────────────────────

export const VERTICALS = [
  {
    id: "commons",
    // Lowercase noun used inline in sentences, e.g. "Total Commons PQs".
    topic: "Commons",
    // Shown as the page <title> and the top-bar brand.
    brandTitle: "Commons PQ Dashboard",
    label: "Commons",

    // --- UK Parliament Written Questions API scope ---
    // The answering body also answers Lords questions (~80/week), but Lords members have
    // no constituency, so every NHS-region feature here would read "Unknown" for
    // them. Switch to "Lords" (or run a second pass) only alongside that caveat.
    house: "Commons",
    answeringBodies: "17", // Parliament's answeringBodies id for the department tracked here
    answeringBodyLabel: "in-scope",

    // null = no searchTerm on the API call: every question the department answers.
    searchTerm: null,
    // Empty = no post-fetch keyword filter. (Set roots here to narrow the fetch down to
    // a single topic; leaving it empty is the un-narrowed case.)
    matchRoots: [],

    // The window, by date tabled. Either an absolute start date (below) or, if that is
    // null, a rolling `lookbackDays` back from today. Anything outside the window is
    // pruned on every refresh.
    //
    // 2024-07-09 is the first sitting day of the current Parliament, so this holds the
    // department's entire Parliament: ~22,600 questions. The list fetch is quick; the
    // expensive half is enriching each answered question's full text from the detail
    // endpoint (~22,000 calls, paced to stay under the API's rate limit — see README).
    windowStart: "2024-07-09",
    lookbackDays: null,

    // Do NOT pre-fetch every answered question's full text into the dataset.
    //
    // The list endpoint gives a ~250-char answer snippet; the full text needs one detail
    // call per question, and at the pace the API tolerates that is ~6 hours for this
    // Parliament's 22,000 answered questions — and it would grow the encrypted payload
    // the browser downloads from ~35MB to ~64MB. The Parliament API sends
    // `access-control-allow-origin: *`, so instead the browser fetches the full answer
    // straight from the detail endpoint when you hover a question (scripts/app.js), and
    // caches it for the session. The dataset stays lean and answers are always current.
    //
    // The cost of this trade: unticking "search question text only" searches the stored
    // snippets, not the full answers. Set this true (and run the long enrichment) if
    // full-answer search ever matters more than page weight.
    enrichAnswers: false,

    // Where the "Subjects" chart gets its buckets. Parliament writes every heading as
    // "Subject: Qualifier" ("GP Practice Lists: Registration", "Dental Services"), so
    // the text before the colon is a ready-made department-wide taxonomy — far better
    // than the hand-curated topic taxonomies, which only ever covered one specialism.
    topicSource: "heading",
  },
];

export const DEFAULT_VERTICAL_ID = "commons";

// Resolve a vertical by id, falling back to the default (and finally the first entry).
export function getVertical(id) {
  return (
    VERTICALS.find((v) => v.id === id) ||
    VERTICALS.find((v) => v.id === DEFAULT_VERTICAL_ID) ||
    VERTICALS[0]
  );
}
