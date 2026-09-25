# Changelog

Each release lists **Affects catalog results** first: anything that can change which plugins get which `capabilities` / `redLines`, or whether a package scans at all. Integrators that pin this package (catalog builds, CI gates) should read that section before bumping. Everything else is under **Other**.

`schemaVersion` is the output-shape version (see [docs/audit-schema.md](docs/audit-schema.md)). It is noted on every release; a bump means the JSON shape or the wording contract broke.

## Unreleased

### Other

- Documented the wording contract: `capabilities` values and `redLines` templates are fixed while `schemaVersion` is `1`, with suggested Chinese for each red-line code ([audit-schema.md](docs/audit-schema.md#wording-contract-capabilities-values-and-redlines-templates)).
- `INTEGRATION.md`: do not combine `--exit-code` with `execFile`-style callers that parse `--json`; a non-zero exit is thrown before the JSON is read.

## 0.1.13 — 2026-09-24

`schemaVersion`: 1. Detection is identical to 0.1.12; safe to pin either.

### Affects catalog results

- None.

### Other

- Settings: the plugin-checkup nav entry gets its own icon instead of the default gear.
- `POSITIONING.md`: sample statistics updated to 0.1.12.

## 0.1.12 — 2026-09-24

`schemaVersion`: 1.

### Affects catalog results

- **Scan limits raised** to 16 MB per file and 64 MB per package (file count stays 4000). The 512 KB / 8 MB limits added in 0.1.11 failed about 12% of a 120-plugin catalog sample on ordinary client bundles; that sample now has no scan failures. `cordis.patch.yml` keeps its own 512 KB limit.
- **RFC 1918 private IPs no longer make a red line.** `10/8`, `172.16/12` and `192.168/16` are still listed in `destinations`, but produce neither `literal-ip` nor `plaintext-http`. Link-local `169.254/16` (cloud metadata) still does.
- **Two identifier URLs are no longer destinations:** the Apple plist DTD `http://www.apple.com/DTDs/PropertyList-1.0.dtd` and the ID3 owner `http://musicbrainz.org`, matched as whole literals only. Other paths on those hosts, subdomains, and concatenated forms are still reported.

### Other

- Settings: the red-line action now shows the real removal command, `dsh plugin --profile <profile> remove <name>`, instead of a `<name>` placeholder.
- `package.json` declares `engines.dsh >= 0.1.0-rc.8` for the Settings page.

## 0.1.11 — 2026-09-24

`schemaVersion`: 1.

### Affects catalog results

- **Incomplete scans fail closed.** An oversized, unreadable or escaping tree lands in `errors` instead of producing a normal report. (The per-file limit introduced here was too low; see 0.1.12.)
- **Runtime targets are always scanned.** A file reached from `main` / `exports` / `bin` or from a static relative import is read whatever its name or extension. Only JSON is skipped as data; binary targets (`.node`, `.wasm`, images, …) are recorded in `coverageNotes` rather than skipped silently. Can add capabilities to packages whose entry pulls in such files.
- **Relative imports under the package's own `node_modules` are followed**; bare imports (`import 'pkg'`) still are not. A symlink that resolves outside the package fails the scan.
- **`cordis.patch.yml` is resolved like source files.** A symlink inside the package is followed, so a core-bundle override behind a symlink now produces `core-tamper`. A patch path that leaves the package, is a directory, or cannot be read lands in `errors` instead of being treated as "no patch".
- `exports` entries under the `types` condition are no longer treated as runtime entry points (removes "optional export not found" coverage noise for declaration files).

### Other

- CLI: opt-in `--exit-code` (0 clear / 1 review / 2 red / 3 scan failed). Default exit code is unchanged.
- CLI: unknown flags, and `--dir` / `--profile` / `--spec` without a value, now exit 1 with an error instead of being ignored. `--dir ""` no longer scans the current directory.
- CLI: profile-mode text output lists the audited plugins (it printed `0 plugin(s)`).
- Local routes: the `Host` header must be a loopback name (DNS rebinding); request bodies are capped at 64 KB (413; invalid JSON is 400).
- Acknowledgements: saved only when the submitted `ackFingerprint` matches a fresh scan (409 otherwise); looked up by the plugin's manifest name with the dependency key as fallback, so npm-alias installs can be acknowledged; a corrupt `trust-ack.json` is no longer overwritten; writes are atomic.
- `decideAckSave` is deprecated; its unused `entry` return goes away with schema v2.
- Docs: added [POSITIONING.md](docs/POSITIONING.md) and [SECURITY.md](SECURITY.md); the package is described as capability disclosure, not a trust score; `clear` is documented as "nothing detected", not a pass.
