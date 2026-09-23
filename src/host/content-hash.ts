import { createHash } from 'node:crypto'

/** SHA-256 hex digest. Host-only; the browser compares the stored result. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}
