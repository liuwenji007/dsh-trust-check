# Catalog noise sample (#401)

Two-step helper for the dsh-market issue: **you download**, the script samples / extracts / scans / writes a table.

This script does **not** fetch anything. Do not optimize `dsh-trust-check` before the first report — the point is the noise of the published scanner.

## 1. Sample

```sh
cd dsh-trust-check
node scripts/catalog-noise.mjs sample
```

Writes `.cache/catalog-sample/`:

- `sample.json` — Top 20 (by `downloads`, excludes `dshmarket`) + Random 20 (npm-published only, seed `20260830`)
- `DOWNLOAD.md` — per-plugin copy-paste commands
- `download.sh` — same commands in one file; run it yourself when the network works

Default catalog: `../dsh-market/data/registry-snapshot.json`. Override with `--catalog`.

## 2. Download (manual)

Put npm pack output into `.cache/catalog-sample/downloads/`. File names can stay as npm wrote them (`pkg-1.2.3.tgz`); scan matches by package name.

Git-only rows: clone into `.cache/catalog-sample/extracted/<id>/` so that directory contains `package.json`.

When the network works, from the work dir:

```sh
bash .cache/catalog-sample/download.sh
```

`npm pack` only writes a tarball. It does not install and does not run lifecycle scripts.

## 3. Scan

```sh
npm run build    # once, if lib/ is missing
node scripts/catalog-noise.mjs scan
```

Missing packs are listed as `missing` and skipped. Re-run after you add more `.tgz` files.

Outputs:

- `.cache/catalog-sample/REPORT.md` — paste this into the issue
- `.cache/catalog-sample/report.json`
- `.cache/catalog-sample/reports/<id>.json` — raw `--json` from each plugin
