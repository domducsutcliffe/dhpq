# Commons PQ Dashboard

An **unofficial personal project**. Not affiliated with, endorsed by, or produced by any
government department or public body — it reads the UK Parliament's open Written Questions
API and nothing else.

A static, password-gated dashboard over House of Commons written questions: search, filter
by party / region / answer status, a volume chart, subject breakdown, hover-to-read
answers, similar-question matching, and an Excel export.

## Running it locally

ES modules and `fetch` don't work over `file://`, so serve the directory:

```sh
python3 -m http.server 8778     # then http://localhost:8778
```

The committed data is encrypted; the page asks for the password on load.

## Configuration

Everything that defines the scope lives in [`config.js`](config.js) — the answering body
id, the house, the date window, and the branding shown in the page. One vertical is
configured; `DEFAULT_VERTICAL_ID` selects it.

## Refreshing the data

```sh
PQ_PASSWORD=<the shared password> node scripts/refresh-data.mjs
PQ_PASSWORD=<the shared password> node scripts/encrypt-data.mjs
```

`refresh-data.mjs` re-fetches the configured window month by month and writes
`data/<id>/*.json`; `encrypt-data.mjs` turns those into the committed `.enc` chunks plus an
unencrypted `questions-index.json` manifest. Only months whose questions changed are
re-encrypted, so an unchanged run adds nothing to git history.

In CI this runs three times each morning (`.github/workflows/refresh-data.yml`) and needs a
`PQ_PASSWORD` repository secret. The plaintext `data/<id>/*.json` is gitignored.

## Deployment

`.github/workflows/deploy-pages.yml` publishes the directory to GitHub Pages on every push
to `main` and after each data refresh.

## How the data is packaged

The dataset is split into chunks: the app decrypts the summary and the first chunk, paints,
then streams the rest in the background and re-renders as they arrive. Answers are not
stored in bulk — the page fetches an answer from the API when you hover it, and caches it
for the session — which keeps the download small and the answers current.
