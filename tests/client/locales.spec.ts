import { describe, expect, it } from 'vitest'
import { en, zh } from '../../src/client/locales.ts'
import { concernText } from '../../src/core/present.ts'
import type { RedLineCode } from '../../src/core/present.ts'

const DECLARED: RedLineCode[] = ['install-script', 'core-tamper']
const DETECTED: RedLineCode[] = ['creds-network', 'plaintext-http', 'literal-ip']

describe('red-line concern wording', () => {
  it('keeps the CLI text identical to the Settings English text', () => {
    for (const code of [...DECLARED, ...DETECTED]) {
      expect(concernText({ code }), code).toBe(en[`concern.${code}`])
    }
  })

  it('marks source-matched red lines as detected in code, and states declarations plainly', () => {
    for (const code of DETECTED) {
      expect(zh[`concern.${code}`], code).toMatch(/^代码中检出：/)
      expect(en[`concern.${code}`], code).toMatch(/^Detected in code: /)
    }
    for (const code of DECLARED) {
      expect(zh[`concern.${code}`], code).not.toMatch(/代码中检出|可能|篡改/)
      expect(en[`concern.${code}`], code).not.toMatch(/Detected in code|May |Tamper/)
    }
  })
})
