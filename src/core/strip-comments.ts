/**
 * Comment blanking for literal scanning. Comments are not shipped behaviour,
 * yet bundlers keep JSDoc, so an example URL in a doc block otherwise reads as
 * a real destination.
 */

const CODE_FILE = /\.(?:[cm]?[jt]sx?)$/i

/** Only code files have comment syntax; prose and skill files are scanned raw. */
export function isCodeFile(file: string): boolean {
  return CODE_FILE.test(file)
}

/**
 * Blank `//` and block comments, preserving every line break and column so
 * reported line numbers still point at the original source.
 *
 * Quote tracking is approximate: a regex literal holding a quote character can
 * desynchronise it. A line that ends inside an unterminated quote is therefore
 * returned untouched, so the failure mode is an unstripped comment rather than
 * a real literal silently disappearing from the report.
 */
export function stripComments(text: string): string {
  const lines = text.split('\n')
  const out: string[] = []
  let inBlock: boolean = false
  let inTemplate: boolean = false

  for (const line of lines) {
    const blockAtStart: boolean = inBlock
    const templateAtStart: boolean = inTemplate
    let result = ''
    let inSingle = false
    let inDouble = false
    let i = 0

    while (i < line.length) {
      const ch = line[i]

      if (inBlock) {
        if (ch === '*' && line[i + 1] === '/') {
          inBlock = false
          result += '  '
          i += 2
          continue
        }
        result += ' '
        i += 1
        continue
      }

      if (inSingle || inDouble || inTemplate) {
        if (ch === '\\' && i + 1 < line.length) {
          result += ch + line[i + 1]
          i += 2
          continue
        }
        if (inSingle && ch === "'") inSingle = false
        else if (inDouble && ch === '"') inDouble = false
        else if (inTemplate && ch === '`') inTemplate = false
        result += ch
        i += 1
        continue
      }

      if (ch === '/' && line[i + 1] === '/') {
        result += ' '.repeat(line.length - i)
        break
      }
      if (ch === '/' && line[i + 1] === '*') {
        inBlock = true
        result += '  '
        i += 2
        continue
      }

      if (ch === "'") inSingle = true
      else if (ch === '"') inDouble = true
      else if (ch === '`') inTemplate = true
      result += ch
      i += 1
    }

    if (inSingle || inDouble) {
      out.push(line)
      inBlock = blockAtStart
      inTemplate = templateAtStart
      continue
    }
    out.push(result)
  }

  return out.join('\n')
}
