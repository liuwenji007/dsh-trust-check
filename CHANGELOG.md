# Changelog

Each release lists **Affects catalog results** first: anything that can change which plugins get which `capabilities` / `redLines`, or whether a package scans at all. Integrators that pin this package (catalog builds, CI gates) should read that section before bumping. Everything else is under **Other**.

`schemaVersion` is the JSON contract version (see [docs/audit-schema.md](docs/audit-schema.md)). It is noted on every release; a bump means the JSON shape or the wording contract broke, or a field became a stable contract.

## Unreleased

`schemaVersion`: 2.

### Affects catalog results

- None.

## 0.2.1 — 2026-10-10

`schemaVersion`: 2. On the 120-plugin sample against 0.2.0, no plugin gains or loses a capability or a red line. 23 plugins gain destinations from template URLs (HTTPS hosts, plus loopback `127.0.0.1` in two); none gains a plaintext-HTTP destination. `opencues-dsh` shows four fewer HTTPS hosts (`www.gov.uk`, `api.coingecko.com`, …) because the new ones fill the 20-row display cap first. `ackFingerprint` changes for 24 plugins, so a red line the user already accepted prompts again after upgrading for `deepseek-harness-tui-dsh-tui`, `dsh-free-search`, `dsh-pet`, and `dsh-plugin-deepseek-vision`.

### Affects catalog results

- **`fetch('blob:…')` / `fetch('data:…')` literals are not `network`** ([#9](https://github.com/liuwenji007/dsh-trust-check/issues/9)). Scheme fetch never enters HTTP. Concatenation (`'blob:' + id`) and variable arguments (`fetch(url)`, even when `url` is a `blob:` URL the host minted at runtime) still count — that over-approximation is unchanged.
- **`www.xfa.org` and `ns.adobe.com` are namespace identifiers, not plaintext destinations** ([#8](https://github.com/liuwenji007/dsh-trust-check/issues/8)). pdf.js bundles the XFA namespace table (`http://www.xfa.org/schema/xci/`, `http://ns.adobe.com/xdp/`, `/xfdf/`, `/xmpmeta/`, …), which raised `uses plaintext http:// to www.xfa.org`. Both hosts are Adobe-held and serve no traffic; each is matched exactly, so `cdn.xfa.org`, `cdn.ns.adobe.com`, `www.adobe.com`, and `<host>.<anything>` still count. `dsh-herta@0.1.5` still has a plaintext-HTTP red line after this: its bundle also carries `http://docx/` and OOXML namespace hosts, which need a separate report.
- **Identifier hosts are only exempt with a path.** A literal such as `"http://www.w3.org"` with nothing after the host is now a destination and can raise the plaintext-HTTP red line, because whatever is appended to it at runtime picks the host. `http://www.w3.org/2000/svg` and the other namespace forms are unaffected. The bare `http://musicbrainz.org` identifier is only exempt as an operand of `==` / `===` / `!=` / `!==`, which is how music-metadata uses it; stored in a table or array (`["http://musicbrainz.org", …]`) it is a destination, because `.join('')` can extend it into another host.
- **Template URLs report their host when `${…}` comes after it.** `` `http://host/x?d=${v}` `` was skipped entirely; the static host is now a destination like any other literal. This also holds when `${…}` directly follows a complete dotted host (`` `https://api.github.com${endpoint}` ``, `` `http://127.0.0.1:${port}` ``), so an empty `${""}` no longer hides a host. The reported host is the static part even if the interpolation extends it at runtime. `${…}` before the host is complete (`` `http://${host}/` ``, `` `http://api.${region}.net/` ``) or after a single-label host (`` `http://localhost${port}` ``) is still not reported.
- **`keychain` / `keytar` only match material methods.** A call like `keychain.add` on a local `Set` is no longer `credentials` and no longer a secret-touch. Imports of those modules, and material methods such as `getPassword` / `setPassword` — called or referenced (`promisify(keytar.findPassword)`, `keytar.default.getPassword`) — still are.
- **Wrapper method names need a bound import to count as a secret read.** `getSecret` / `getToken` / `findAnyCredential` on a bare `keychain` / `keytar` name, or on an alias of one (`const k = keychain`), no longer feed `creds-network`; after `require('keychain')` or `import … from 'keytar'` they still do. `getPassword` / `getCredentials` / `findPassword` / `findCredentials` count either way.
- **Dev-only files drop out when `package.json` `files` parses exactly.** A `link:` or source-directory scan no longer counts files npm would not publish (for example `scripts/` that shipped code does not import). That can remove a capability or a red line, and it changes `ackFingerprint`, so a local acknowledgment may need to be renewed. A registry tarball already contains only published files, so a catalog record changes only if the matcher drops a file the tarball actually has. On the current 120-plugin extract it drops none, so capabilities and red lines there are unchanged. Patterns with braces, character classes, extglob, or escapes are not filtered. Negation is ignored (extra files stay). `preinstall` / `install` / `postinstall` / `prepare` targets, manifest entries, and files imported by shipped code are still scanned. The scanner also keeps root `LICENSE` / `README` / `NOTICE` / `CHANGELOG` / `HISTORY` / `CHANGES` when `files` omits them. npm 10.9.4 itself always packs `LICENSE`, `README`, and `COPYING`, not `NOTICE`.
- **`files: ["*"]` and `files: ["dir/*"]` keep nested published files.** A lone `*` matches every path, and a pattern ending in `/*` is read as `/**`, which is what npm-packlist packs. The previous matcher treated `*` as one path segment, so a published `lib/payload.js` or `skills/*.md` could disappear from capabilities, red lines, and skill injections while the coverage note called it dev-only. `src*` still does not include `src/a.js`. A string `browser` entry is scanned when `files` omits it; a `browser` object is not an extra entry. A static backtick specifier (`require(\`../utils/index.mjs\`)`) is followed, and so is `require("./dir")` when that directory's `package.json` `main` is `index.cjs`. A `main` that points at a missing file outside the package falls through to that directory's `index.js`, which is what Node runs; an existing outside file is not read. An interpolated template stays a coverage note and is not followed.

### Other

- Display-only context on evidence, destinations, and secret touches: which entry reaches the file (`server` / `client` / `cli`), and a suspected bundled dependency when a sourcemap line maps into `node_modules`. Destination rows also carry a usage label (`request`, `compare`, `namespace`, `link`, `assigned`, `unknown`) and up to five `file:line` sites. None of this changes `capabilities`, `redLines`, `score`, or `ackFingerprint`. `schemaVersion` stays 2.
- Docs: relative-path `fetch('/api')` is *not* `network` (the previous README line said it still counted). Matches the scanner and the `blob:` / `data:` carve-out above.
- Bind / broadcast addresses (`0.0.0.0`, `255.255.255.255`) and RFC 5737 documentation IPs stay in destinations but are no longer labeled public IP, and fold with the safe list — matching the literal-IP red line, which already skipped them. Link-local `169.254/16` is not softened to private.

## 0.2.0 — 2026-10-03

`schemaVersion`: 2. Adds `facts[]` (`{ id, value, evidence }`) and `evidence.rule`. The bump is for `facts[].id`, which is a stable filter key from this release on. No schema 1 field is removed or renamed, so a reader written for schema 1 still parses the output once it accepts `2`. Capability values and red-line templates are unchanged from schema 1. Comment blanking changed, so a catalog record can gain or lose a capability that lived only in a mis-read comment or in code the previous blanker dropped. On the 120-plugin sample against 0.1.14, `dsh-engram` loses `llm` (the only evidence was a doc comment) and two plugins (`dsh-permission-rules`, `michengai-dsh-agency-agents`) lose `dynamic-code`. No plugin gains a capability or a red line. `creds-network` stays a red line.

### Affects catalog results

- **Comment blanking follows regex literals and template interpolations.** A comment that the previous blanker left in the scan can stop counting, and code it had blanked is scanned. When a template, block comment, or regex is left unclosed, or tokenization fails, that file is scanned raw and the report gains a `coverageNotes` entry (`comment stripping fell back to raw text in <file>`). The note does not change `verdict()`.
- **Constant `eval` / `new Function` is no longer `dynamic-code`.** Every argument must be a complete string literal, the call must close on the same line, and no literal may name `require`, `import`, `process`, `globalThis`, `Function`, `eval`, `constructor`, or a similar way out. `new Function("return this")` is exempt. `new Function("a", body)`, `eval("" || code)`, and `eval("require")("child_process")` still are `dynamic-code`.

### Other

- Suggested English and Chinese for each capability value are in [audit-schema.md](docs/audit-schema.md#capabilities-values). Wording should not add a scope or a mechanism the scan did not observe.
- Coverage notes for a computed `require` module name, `process.binding` / `process.dlopen`, and `eval` / `Function` wrapped around `atob` or `Buffer.from`. On the 120-plugin sample these matched no plugin. The same notes are also `facts[]` ids (`computed-module-name`, `native-binding`, `decoded-eval`).
- `facts[]` lists every rule that fired, including one whose evidence rows the 40-row cap dropped; that fact has empty `evidence`.
- `readNpmProvenance(name, version)` reads the registry attestation and reports the repository and commit it names. It does not check the signature. `repositoryMatches` compares only github.com URLs, so a declared URL that merely contains `github.com/owner/repo` in its path does not match. A failed lookup throws so the caller can omit the field; a 404 is `{ present: false }`, which is not a claim that the package is unsafe.
- Settings: the "nothing detected" note now names obfuscated code alongside dynamic import, runtime-built URLs, and dependency-tree behavior.
- CLI tests no longer inherit `DSH_PROFILE` from the host. A profile name the home does not have still exits 3, and a test locks that.
- Docs: [INTEGRATION.md](docs/INTEGRATION.md) says when a catalog should bump its pin, why a `schemaVersion` change also needs a reader change, and why a detection change needs `PROBE_ALL=1`. [POSITIONING.md](docs/POSITIONING.md) keeps `creds-network` and the `fs-read` import branch, and holds the market “new in this version” display until `scripts/capability-changes.mjs` has a few weeks of version changes.
- `scripts/strip-oracle.mjs` compares comment blanking with the TypeScript parser. On the 120-plugin sample: 0 code lines deleted, 129 comment lines left in place across 4 files.

## 0.1.14 — 2026-09-25

`schemaVersion`: 1. Detection is identical to 0.1.13: same `capabilities` and `redLines` on every package, and the `redLines` sentences are unchanged. Upgrading changes no catalog record.

### Affects catalog results

- None.
- The JSX `placeholder` false positive mentioned in #401 has not produced a red line since 0.1.12: the value is an RFC 1918 address, which is now listed as a destination only. `placeholder` attributes get no exemption of their own, because a syntactic exemption can be borrowed (`{ placeholder: "<public ip>" }` read back into a request) to hide a real destination.

### Other

- Red-line concerns in Settings and in the CLI's "why be careful" list now use the same factual wording as the [suggested translations](docs/audit-schema.md#wording-contract-capabilities-values-and-redlines-templates): declarations are stated plainly ("Runs scripts at install time", "Overrides or disables a DSH core bundle"), source matches are prefixed "Detected in code:". Replaces "May run arbitrary code" and "Tamper with a core bundle". A test keeps the CLI and Settings English text identical.
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
