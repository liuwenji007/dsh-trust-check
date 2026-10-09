import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { auditPlugin } from '../../src/core/audit.ts'
import { collectPlugin } from '../../src/fs.ts'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..')

// CI's `self-scan with --exit-code` step scans the built lib/, which is
// bundled from src/. Scanning src/ here catches a red line on the scanner's
// own tables before the build, without depending on lib/ existing.
describe('self-scan', () => {
  it('raises no red line on the scanner source', () => {
    const report = auditPlugin(collectPlugin(join(ROOT, 'src'), 'self'))
    expect(report.redLines).toEqual([])
  })
})
