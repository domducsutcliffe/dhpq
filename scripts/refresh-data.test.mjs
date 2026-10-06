import test from "node:test";
import assert from "node:assert/strict";
import { createRefreshPlan } from "./refresh-plan.mjs";
import { questionHouse, isCommonsQuestion } from "../config.js";
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

process.env.LIST_DELAY_MS = "0";
const { mapQuestion, buildSummary, fetchWindow } = await import("./refresh-data.mjs");
const base = {
  today: "2026-10-06", windowStart: "2024-07-09", houses: ["Commons", "Lords"],
  previous: { source: { completedHouses: ["Commons", "Lords"] }, refresh: { answersAt: "2026-10-01" } },
};

test("priority pass fetches recent questions without answer queries or historical backfill", () => {
  const plan = createRefreshPlan({ ...base, mode: "recent", previous: {} });
  assert.deepEqual(plan.requests, [{ from: "2026-09-29", to: "2026-10-06", dateField: "tabledWhen", houses: base.houses }]);
  assert.deepEqual(plan.completedHouses, ["Commons"]);
  assert.deepEqual(plan.refresh, { recentAt: "2026-10-06" });
});

test("answer pass catches answers to old questions and leaves priority watermark alone", () => {
  const previous = { ...base.previous, refresh: { recentAt: "2026-10-06", answersAt: "2026-06-01" } };
  const plan = createRefreshPlan({ ...base, previous, mode: "answers" });
  assert.deepEqual(plan.requests, [{ from: "2026-05-31", to: "2026-10-06", dateField: "answeredWhen", houses: base.houses }]);
  assert.equal(plan.refresh.recentAt, "2026-10-06");
  assert.equal(plan.refresh.answersAt, "2026-10-06");
  assert.equal(previous.refresh.answersAt, "2026-06-01", "planning must not mutate saved progress");
});

test("missed priority runs widen the window and respect the Parliament start", () => {
  const plan = createRefreshPlan({ ...base, mode: "recent", previous: { refresh: { recentAt: "2024-01-01" } } });
  assert.equal(plan.requests[0].from, base.windowStart);
});

test("only the lower-priority pass backfills a newly enabled house", () => {
  const plan = createRefreshPlan({ ...base, mode: "answers", previous: {} });
  assert.equal(plan.requests.length, 2);
  assert.deepEqual(plan.requests[1], { from: base.windowStart, to: base.today, dateField: "tabledWhen", houses: ["Lords"] });
  assert.deepEqual(plan.completedHouses, base.houses);
});

test("full rebuild covers both houses and invalid modes are rejected", () => {
  const plan = createRefreshPlan({ ...base, mode: "all", forceFull: true });
  assert.equal(plan.replace, true);
  assert.equal(plan.requests[0].from, base.windowStart);
  assert.deepEqual(plan.completedHouses, base.houses);
  assert.throws(() => createRefreshPlan({ ...base, mode: "typo" }), /Invalid refresh mode/);
});

test("Lords titles cannot be mistaken for constituencies; legacy Commons remains supported", () => {
  const lookup = new Map([["london", { nation: "England", nhsRegion: "London" }]]);
  const q = { id: 1, uin: "HL123", dateTabled: "2026-09-01", askingMember: { name: "Baron Example", memberFrom: "London" } };
  const mapped = mapQuestion({ value: q, sourceHouse: "Lords" }, lookup);
  assert.equal(mapped.house, "Lords");
  assert.equal(mapped.member.constituency, "");
  assert.equal(mapped.region.nhsRegion, "");
  assert.equal(mapped.region.sourceBoundary, "not-applicable");
  assert.equal(questionHouse({ uin: "123" }), "Commons");
  assert.equal(questionHouse({ uin: "hl123" }), "Lords");
  assert.equal(isCommonsQuestion(mapped), false);
});

test("summary totals include Lords but regional counts include Commons only", () => {
  const lookup = new Map([["london", { nation: "England", nhsRegion: "London" }]]);
  const raw = { dateTabled: "2026-09-01", dateAnswered: "2026-09-05", askingMember: { name: "Example", party: "Test", memberFrom: "London" } };
  const commons = mapQuestion({ value: { ...raw, id: 1, uin: "123" }, sourceHouse: "Commons" }, lookup);
  const lords = mapQuestion({ value: { ...raw, id: 2, uin: "HL123" }, sourceHouse: "Lords" }, lookup);
  const summary = buildSummary([commons, lords], [], [], { version: "none", concepts: [] });
  assert.equal(summary.totals.questions, 2);
  assert.equal(summary.totals.answered, 2);
  assert.deepEqual(summary.regions, [{ key: "London", count: 1 }]);
  assert.deepEqual(summary.monthly[0].byRegion, { London: 1 });
});

test("API queries page both houses with bounded answer dates and no tabled restriction", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    const params = new URL(url).searchParams;
    calls.push(Object.fromEntries(params));
    const house = params.get("house");
    const skip = Number(params.get("skip"));
    const count = house === "Commons" ? 101 : 1;
    const results = Array.from({ length: Math.min(100, count - skip) }, (_, i) => ({ value: {
      id: (house === "Commons" ? 0 : 1000) + skip + i, uin: `${house === "Lords" ? "HL" : ""}${skip + i}`,
      dateTabled: "2024-07-10", dateAnswered: "2026-09-01",
    } }));
    return new Response(JSON.stringify({ results, totalResults: count }));
  };
  try {
    const rows = await fetchWindow("2026-08-31", "2026-09-01", "answeredWhen");
    assert.equal(rows.length, 102, "duplicates across chunks are merged by ID");
    assert.equal(calls.length, 6);
    assert(calls.every(p => p.answeredWhenFrom && p.answeredWhenTo && !p.tabledWhenFrom));
    assert.deepEqual(calls.map(p => p.skip), ["0", "100", "0", "0", "100", "0"]);
    assert.equal(rows.find(r => r.value.id === 1000).sourceHouse, "Lords");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("priority output survives a failed catch-up; a successful catch-up updates old answers", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pq-refresh-test-"));
  try {
    await mkdir(path.join(root, "scripts"));
    await mkdir(path.join(root, "data/commons"), { recursive: true });
    for (const file of ["refresh-data.mjs", "refresh-plan.mjs"]) {
      await copyFile(new URL(file, import.meta.url), path.join(root, "scripts", file));
    }
    await copyFile(new URL("../config.js", import.meta.url), path.join(root, "config.js"));
    const old = mapQuestion({ sourceHouse: "Commons", value: {
      id: 1, uin: "100", dateTabled: "2024-07-17", questionText: "An old question?",
      askingMember: { name: "Example" },
    } }, new Map());
    const dataPath = path.join(root, "data/commons/questions.json");
    await writeFile(dataPath, JSON.stringify({ questions: [old] }));
    await writeFile(path.join(root, "data/commons/summary.json"), JSON.stringify({ source: { completedHouses: ["Commons", "Lords"] } }));
    await writeFile(path.join(root, "data/constituency-lookup-cache.json"), JSON.stringify({ lookup: {}, records: [] }));
    await writeFile(path.join(root, "mock.mjs"), `
      globalThis.setTimeout = (fn) => { fn(); return 0; };
      globalThis.fetch = async (url) => {
        const p = new URL(url).searchParams;
        const answers = p.has("answeredWhenFrom");
        if (answers && process.env.FAIL_ANSWERS === "1") throw new Error("Mock answer API outage");
        const house = p.get("house");
        const today = new Date().toISOString().slice(0, 10);
        const q = answers
          ? { id: 1, uin: "100", dateTabled: "2024-07-17", dateAnswered: today, answerText: "An answer to the old question." }
          : { id: house === "Lords" ? 2 : 3, uin: house === "Lords" ? "HL200" : "300", dateTabled: today, dateAnswered: today, answerText: "A new answer." };
        const results = answers && house === "Lords" ? [] : [{ value: { ...q, questionText: "A complete question?", askingMember: { name: "Example" } } }];
        return new Response(JSON.stringify({ results, totalResults: results.length }));
      };
    `);
    const run = (mode, fail = false) => spawnSync(process.execPath,
      ["--import", path.join(root, "mock.mjs"), path.join(root, "scripts/refresh-data.mjs"), `--mode=${mode}`, "--no-enrich"],
      { cwd: root, encoding: "utf8", env: { ...process.env, FAIL_ANSWERS: fail ? "1" : "0", LIST_DELAY_MS: "0" } });
    const recent = run("recent");
    assert.equal(recent.status, 0, recent.stderr);
    const saved = await readFile(dataPath, "utf8");
    const rows = JSON.parse(saved).questions;
    assert.equal(rows.length, 3);
    assert.equal(rows.find(q => q.id === 2).house, "Lords");
    assert.equal(rows.find(q => q.id === 3).answerText, "A new answer.");
    assert.equal(rows.find(q => q.id === 1).answered, false);
    const failed = run("answers", true);
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /Mock answer API outage/);
    assert.equal(await readFile(dataPath, "utf8"), saved);
    const answered = run("answers");
    assert.equal(answered.status, 0, answered.stderr);
    const updated = JSON.parse(await readFile(dataPath, "utf8")).questions;
    assert.equal(updated.length, 3);
    assert.equal(updated.find(q => q.id === 1).answerText, "An answer to the old question.");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
