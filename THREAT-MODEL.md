# Threat model for DSH plugin capability disclosure

What this scanner can and cannot claim, mapped to the attacks a malicious DSH
plugin can actually mount. This is the checklist to hold against when adding
or tightening a rule — and the honest statement of where static analysis
stops. It exists so rule work is driven by a threat list, not by vibes.

> This project is a **static capability-disclosure scanner**, not a security
> product and not an antivirus. It proves what a plugin *touches*; it never
> vouches for what a plugin *means to do*. Every rule below is a "detected X"
> claim. None is a "guaranteed no Y" claim. See
> [CONTRIBUTING.md](CONTRIBUTING.md) for the rule discipline that keeps the
> scanner from flagging its own rule table.

The five attack classes below follow the shape of OWASP's Top 10 for LLM
applications and agent-supply-chain research, translated to what a plugin in
DeepSeek Harness can actually do.

---

## 1. Prompt injection / context poisoning

**Attack.** The plugin ships skill text, a `systemPrompt` registration, or
documentation that instructs the model to ignore its rules and exfiltrate
conversation history or act on attacker-controlled commands. Research on
SKILL.md / AGENTS.md poisoning shows instructions can hide inside
ordinary-looking skill files. The dangerous case is not the plugin that
obviously says "send everything to evil.test" — it is the one whose skill
text reads like a feature and behaves like a backdoor when the model is
already in a vulnerable context.

**What trust-check proves.**

- A plugin registers a system prompt (`systemPrompt`, `ctx.skills.register`,
  system-prompt assembly).
- A plugin ships skill/instruction text, and roughly how much
  (`injectedTokensEstimate`, bytes of quoted literals).
- A patch overrides or disables a `@deepseek-ai/*` core bundle (that is a
  separate, worse class — see §5).

**Where static analysis stops.** The *content* of a skill file is opaque to a
regex scanner. A malicious instruction that reads like a feature is
indistinguishable from a real feature. We detect the shape (a skill exists,
it is N bytes, it registers a prompt) — never the intent of its prose.

**Rule-maintenance questions.**

- Does a new plugin have a suspiciously large skill/prompt payload for what it
  claims to do? (A calendar plugin shipping 40 KB of prompt text is a shape
  worth surfacing even though we cannot read the text.)
- Does the injection finding pair with a network capability? That is the
  exfiltration shape: instructions present + a way to send data out.

## 2. Excessive agency / capability overreach

**Attack.** The plugin requests more capability than its stated purpose needs:
a calendar plugin that shells out, a UI theme that reads `.ssh`, a formatter
that opens sockets. In an agent, capability is not permission — but a static
scanner cannot see the harness's runtime permission model, so the closest
provable statement is "this plugin's code can do X".

**What trust-check proves.**

- The capability set: shell, fs-read, fs-write, network, credentials, env,
  subagent, host-runtime, llm, dynamic-code — each with `file:line` evidence.
- The red-line combination: credentials **and** network together (the classic
  exfiltration shape) — a deliberate over-approximation, because either alone
  is often legitimate.

**Where static analysis stops.** Whether a capability is *appropriate* for the
plugin's purpose is a judgment call the scanner cannot make. A photo tool
legitimately reads files and hits a CDN. Trust-check says what it touches; the
user decides whether that matches why they installed it.

**Rule-maintenance questions.**

- Is there a new capability pattern whose *call site* is real (see the
  `delegate(` false-positive history: a method named like an API is not the
  API)? Match the DSH interface shape, not the word.
- Does the rule fire on prose or comments? (Comments are stripped before the
  scan; a rule that only exists to catch comment text is wrong.)

## 3. Supply-chain poisoning

**Attack.** The plugin itself is honest; its dependency tree is not. A
typosquatted package, a compromised transitive dependency, or a version
range that silently resolves to a newer, malicious release.

**What trust-check proves.**

- The declared `repository` and whether the install spec pins an exact
  version/commit (`pinned`). A moving target (`latest`, `^1.2.3`, a git ref
  without a commit hash) is surfaced.
- Install-time scripts (`preinstall` / `install` / `postinstall`) — these run
  on the consumer's machine during a registry install and are a red line.
  `prepare` is deliberately **not** a red line (registry installs do not run
  it; git installs and `npm pack`/`publish` do), so it is a small deduction
  with a reason that says exactly when it runs.

**Where static analysis stops.** `node_modules` is never scanned. A poisoned
dependency's behavior is invisible to `--dir` scans of the plugin's own tree.
The scanner reports the shape (unpinned, scripts, missing repo); it cannot
read the dependency graph's contents.

**Rule-maintenance questions.**

- Should a dependency scope that is known-dangerous or known-high-risk get a
  pattern? (Currently dependency *scope* only drives the `host-runtime`
  derivation. Broad dependency-name matching is a false-positive minefield —
  weigh it against the `ofetch`-style client list already in `seams.ts`.)
- Is `prepare`'s downgraded treatment still accurate as install flows change?
  (It is correct for npm registry installs; revisit if the market ever installs
  from git.)

## 4. Install-time code execution

**Attack.** `install` / `postinstall` scripts run arbitrary code on the
consumer's machine before the plugin is ever audited. By the time a
`--dir` scan runs, the damage may already be done.

**What trust-check proves.** Which install-time scripts exist, as a red line
with the script names in the message. The CLI's `--dir` mode can scan an
extracted tarball *before* install, which is the only posture that beats this
attack class — and even then, a market's unpack/install step may have already
run scripts.

**Where static analysis stops.** What the install script *does* is not read.
A `postinstall` that downloads and runs a second-stage payload is invisible;
only its existence is proven.

**Rule-maintenance questions.**

- Keep install-script detection at the *declaration* level (`scripts` field),
  not by trying to interpret the script body — body interpretation is a
  rabbit hole with unbounded false negatives.
- The `prepare` downgrade (§3) must not silently leak back into the
  install-script red line — the two code paths (`INSTALL_SCRIPTS` vs
  `PREPARE_SCRIPTS` in `provenance.ts`) are separate on purpose.

## 5. Bundle tampering / privilege escalation

**Attack.** The plugin's `cordis.patch.yml` overrides or disables a
`@deepseek-ai/*` core bundle — effectively rewriting the harness itself
rather than adding to it. This is the worst class: it does not need its own
capabilities because it edits the thing that grants capabilities.

**What trust-check proves.** Patch findings of kind `override` / `disable`
against `@deepseek-ai/*` bundles are a red line; overrides of community
bundles are a deduction. This is `injection.ts` + `score.ts`, not the
capability scan — a separate seam on purpose.

**Where static analysis stops.** What the override *changes* is not diffed.
Disabling a core bundle could be a legitimate workaround or a hijack; the
scanner proves the tampering happened, not the tamperer's intent.

**Rule-maintenance questions.**

- Core-bundle matching uses the `@deepseek-ai/` scope (`id` **or** `name`).
  If the harness adds new core scopes, the seam must follow — this is a data
  table, not engine code, and updating it should be a one-line change.
- A patch that only adds its own slots/views (no override/disable) must stay
  out of this class. Over-broad patch matching would flag every plugin with a
  `cordis.patch.yml`.

---

## What this scanner will never prove

Three limits are physical, not implementation gaps. Designing a rule that
pretends to cross them is how scanners become liars.

1. **Intent is invisible.** `fetch(url)` — the scanner sees the call, not
   whether `url` is the user's expected endpoint or an attacker's. Semantics
   are not recoverable from a regex over source text.
2. **Runtime is invisible.** Dynamically built URLs, `import()`, obfuscated
   `eval` exist only at execution time. A static scan of source cannot see
   what does not exist yet. (See §1: a variable `fetch(host)` is therefore
   conservatively treated as egress — presence, never absence.)
3. **Dependencies are invisible.** `node_modules` behavior is out of scope.
   The plugin's own tree is the audit boundary.

The value of this scanner is exactly in honoring these three limits while
proving everything provable inside them. "Static scan found nothing" is
*no information* — it must never be rendered as a safety claim. That is the
single most important UI rule, and it is why an empty card area is empty,
not labeled "looks clean".

## How to use this document

- **Adding or tightening a rule** → name the attack class it addresses, then
  check the rule-maintenance questions for that class. A rule that addresses
  no named class is probably noise.
- **Reviewing a 40-plugin sample** → classify every finding by class (§1–§5).
  "Capability X is present" is only actionable when you can say which attack
  it would enable or which legitimate purpose it serves.
- **Explaining the tool to someone (fkysly, a market maintainer, a user)** →
  lead with the five classes and the three limits. It makes the "chips only
  when something was found" UI rule self-evident instead of arbitrary.
