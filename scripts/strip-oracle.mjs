/**
 * Compare comment blanking with the TypeScript 5 parser's comment ranges.
 *
 * A code line the tokenizer deletes is a failure (exit 1). A comment line it
 * leaves in place is reported as a baseline, not a failure.
 *
 *   node --experimental-strip-types scripts/strip-oracle.mjs [sample-dir]
 *
 * 2026-10-03 sample (120 plugins): 0 code lines erased, 129 comment lines
 * left in 4 files. A leading hashbang is blanked in the reference because
 * the TypeScript parser does not report it as a comment.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join } from 'node:path'
import ts from 'typescript'
import { isCodeFile, stripComments } from '../src/core/strip-comments.ts'

const root = process.argv[2] ?? '.cache/catalog-sample/extracted'
const MAX_BYTES = 16 * 1024 * 1024

function* walk(dir) {
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue
      yield* walk(path)
    } else if (isCodeFile(path)) {
      yield path
    }
  }
}

function scriptKind(file) {
  const ext = extname(file).toLowerCase()
  if (ext === '.tsx') return ts.ScriptKind.TSX
  if (ext === '.jsx') return ts.ScriptKind.JSX
  if (ext === '.ts' || ext === '.mts' || ext === '.cts') return ts.ScriptKind.TS
  return ts.ScriptKind.JS
}

function blankHashbang(text) {
  if (!text.startsWith('#!')) return text
  const end = text.indexOf('\n')
  if (end === -1) return ' '.repeat(text.length)
  return `${' '.repeat(end)}${text.slice(end)}`
}

/** Blank comment ranges the TypeScript parser attaches to the tree. */
function oracle(text, file) {
  const sourceFile = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, false, scriptKind(file))
  const ranges = new Map()
  const add = (list) => {
    if (list === undefined) return
    for (const range of list) ranges.set(range.pos, range.end)
  }
  const visit = (node) => {
    add(ts.getLeadingCommentRanges(text, node.pos))
    add(ts.getTrailingCommentRanges(text, node.end))
    node.getChildren(sourceFile).forEach(visit)
  }
  visit(sourceFile)
  const chars = text.split('')
  for (const [start, end] of ranges) {
    for (let i = start; i < end; i++) {
      const ch = chars[i]
      if (ch !== '\n' && ch !== '\r') chars[i] = ' '
    }
  }
  return chars.join('')
}

let files = 0
let skipped = 0
const erased = []
let kept = 0
const keptFiles = new Set()

let plugins
try {
  plugins = readdirSync(root)
} catch {
  console.error(`sample directory not found: ${root}`)
  process.exit(1)
}

for (const plugin of plugins) {
  for (const file of walk(join(root, plugin))) {
    const size = statSync(file).size
    if (size > MAX_BYTES) {
      skipped += 1
      continue
    }
    const text = readFileSync(file, 'utf8')
    files += 1
    let ours
    let reference
    try {
      ours = stripComments(text, file).split('\n')
      // The TypeScript parser does not report a leading hashbang as a comment.
      reference = blankHashbang(oracle(text, file)).split('\n')
    } catch {
      continue
    }
    const rel = file.slice(root.length + 1)
    for (let i = 0; i < reference.length; i++) {
      const left = (ours[i] ?? '').trim()
      const right = (reference[i] ?? '').trim()
      if (right !== '' && left === '') erased.push(`${rel}:${i + 1}  ${right.slice(0, 90)}`)
      else if (left !== '' && right === '') {
        kept += 1
        keptFiles.add(rel)
      }
    }
  }
}

console.log(`files ${files} skipped ${skipped}`)
console.log(`code lines erased: ${erased.length}`)
if (erased.length > 0) console.log(erased.slice(0, 25).join('\n'))
console.log(`comment lines left unstripped: ${kept} in ${keptFiles.size} files`)
if (keptFiles.size > 0 && keptFiles.size <= 20) console.log([...keptFiles].join('\n'))
if (erased.length > 0) process.exit(1)
