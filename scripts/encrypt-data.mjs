#!/usr/bin/env node
// ── encrypt-data.mjs ─────────────────────────────────────────────────────────
// Encrypts the dashboard JSON data files using AES-256-GCM with a key derived
// from a password via PBKDF2. The browser app decrypts them at runtime with the
// Web Crypto API and the same password.
//
// Output is a compact BINARY container, gzipped before encryption, and the questions are
// split into CHUNKS so the browser can render the first page immediately and stream the
// rest in the background.
//
//   - gzip: encrypted bytes don't compress, but the JSON does (~5x), so the committed
//     file and the download shrink from ~28MB to ~5MB.
//   - chunks: questions.json becomes questions-0.json.enc, questions-1.json.enc, … plus
//     an unencrypted questions-index.json manifest ({chunks,chunkSize,total}). The app
//     decrypts chunk 0 and paints, then fills in the rest.
//
// Container layout (little-endian):
//   0   magic       4 bytes  "PQE1" = utf8 payload · "PQE2" = gzip-compressed payload
//   4   iterations  uint32   PBKDF2 iteration count
//   8   salt       16 bytes
//   24  iv         12 bytes  (AES-GCM nonce)
//   36  tag        16 bytes  (AES-GCM auth tag)
//   52  ciphertext rest      (decrypts to gzip bytes for PQE2, raw utf8 for PQE1)
//
// The password itself is never written down here — it lives in the PQ_PASSWORD Actions
// secret and in whatever you share with readers. A literal in this file would hand the
// dataset to anyone who can read the repo.
//
// Usage:
//   PQ_PASSWORD=<the shared password> node scripts/encrypt-data.mjs
//   node scripts/encrypt-data.mjs --password=<the shared password>
// ─────────────────────────────────────────────────────────────────────────────

import { readFile, writeFile, readdir, unlink } from "node:fs/promises";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getVertical, DEFAULT_VERTICAL_ID } from "../config.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const dataDir = path.join(repoRoot, "data");

const VERTICAL = getVertical(DEFAULT_VERTICAL_ID);
const verticalDir = path.join(dataDir, VERTICAL.id);

// Resolve password from CLI arg or env var
const pwArg = process.argv.find((a) => a.startsWith("--password="));
const PASSWORD = pwArg ? pwArg.split("=")[1] : process.env.PQ_PASSWORD;

if (!PASSWORD) {
  console.error("Error: supply a password via --password=<pw> or PQ_PASSWORD env var.");
  process.exit(1);
}

const PBKDF2_ITERATIONS = 100_000;
const SALT_BYTES = 16;
const IV_BYTES = 12; // AES-GCM standard nonce length
// How many questions per encrypted chunk. Small enough that chunk 0 paints fast; the
// rest stream in the background. ~2000 gzips to a few hundred KB.
const QUESTIONS_CHUNK_SIZE = Number(process.env.CHUNK_SIZE || 2000);

// Encrypt a string. Gzips first (magic "PQE2") unless the payload is tiny, in which case
// the raw form ("PQE1") avoids the gzip overhead for no benefit.
function encrypt(text, password) {
  const raw = Buffer.from(text, "utf8");
  const gzip = raw.length > 512;
  const payload = gzip ? gzipSync(raw, { level: 9 }) : raw;

  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  const header = Buffer.alloc(8);
  header.write(gzip ? "PQE2" : "PQE1", 0, "ascii");
  header.writeUInt32LE(PBKDF2_ITERATIONS, 4);
  return Buffer.concat([header, salt, iv, authTag, encrypted]);
}

async function encryptFile(filePath) {
  const plaintext = await readFile(filePath, "utf8");
  const encPath = filePath + ".enc";
  const container = encrypt(plaintext, PASSWORD);
  await writeFile(encPath, container);
  const sizeKb = (container.length / 1024).toFixed(1);
  console.log(`  ✓ ${path.relative(repoRoot, filePath)} → ${path.relative(repoRoot, encPath)} (${sizeKb} KB)`);
}

// Split questions.json into encrypted, gzipped chunks + an unencrypted manifest.
async function encryptQuestionsChunked(filePath) {
  const parsed = JSON.parse(await readFile(filePath, "utf8"));
  const questions = parsed.questions || [];

  // Drop any chunk files from a previous (possibly larger) run so stale high-index
  // chunks don't linger in the repo, and remove the old single-file .enc.
  for (const name of await readdir(verticalDir)) {
    if (/^questions-\d+\.json\.enc$/.test(name) || name === "questions.json.enc") {
      await unlink(path.join(verticalDir, name));
    }
  }

  const chunkCount = Math.max(1, Math.ceil(questions.length / QUESTIONS_CHUNK_SIZE));
  let totalKb = 0;
  for (let i = 0; i < chunkCount; i += 1) {
    const slice = questions.slice(i * QUESTIONS_CHUNK_SIZE, (i + 1) * QUESTIONS_CHUNK_SIZE);
    const container = encrypt(JSON.stringify({ questions: slice }), PASSWORD);
    await writeFile(path.join(verticalDir, `questions-${i}.json.enc`), container);
    totalKb += container.length / 1024;
  }

  const manifest = {
    chunks: chunkCount,
    chunkSize: QUESTIONS_CHUNK_SIZE,
    total: questions.length,
  };
  await writeFile(
    path.join(verticalDir, "questions-index.json"),
    `${JSON.stringify(manifest)}\n`,
    "utf8",
  );
  console.log(
    `  ✓ questions.json → ${chunkCount} encrypted chunk(s), ${(totalKb / 1024).toFixed(1)} MB total ` +
      `(${questions.length.toLocaleString()} questions)`,
  );
}

async function main() {
  console.log(`Encrypting data files for vertical "${VERTICAL.id}"...`);
  await encryptFile(path.join(verticalDir, "summary.json"));
  await encryptQuestionsChunked(path.join(verticalDir, "questions.json"));
  console.log("Encryption complete.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
