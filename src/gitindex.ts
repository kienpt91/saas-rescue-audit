/**
 * Reads the list of tracked paths from a `.git/index` file (formats 2 and 3).
 * Returns null for anything else, including format 4, which compresses path prefixes.
 */
export function parseGitIndex(buf: Uint8Array): Set<string> | null {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf.length < 12) return null;
  if (String.fromCharCode(buf[0]!, buf[1]!, buf[2]!, buf[3]!) !== "DIRC") return null;
  const version = view.getUint32(4);
  if (version !== 2 && version !== 3) return null;
  const count = view.getUint32(8);
  const tracked = new Set<string>();
  const decoder = new TextDecoder();
  let offset = 12;
  for (let i = 0; i < count; i++) {
    const fixed = 62;
    if (offset + fixed > buf.length) return null;
    const flags = view.getUint16(offset + 60);
    const extended = version === 3 && (flags & 0x4000) !== 0;
    const pathStart = offset + fixed + (extended ? 2 : 0);
    let end = pathStart;
    while (end < buf.length && buf[end] !== 0) end++;
    if (end >= buf.length) return null;
    tracked.add(decoder.decode(buf.subarray(pathStart, end)));
    const entryLength = end - offset + 1;
    offset += Math.ceil(entryLength / 8) * 8;
  }
  return tracked;
}
