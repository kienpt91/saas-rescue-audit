/** Builds a `.git/index` image (format 2 by default) listing the given paths. */
export function buildIndex(paths: string[], version = 2): Uint8Array {
  const encoder = new TextEncoder();
  const entries = paths.map((path) => {
    const bytes = encoder.encode(path);
    const entry = new Uint8Array(Math.ceil((62 + bytes.length + 1) / 8) * 8);
    new DataView(entry.buffer).setUint16(60, Math.min(bytes.length, 0xfff));
    entry.set(bytes, 62);
    return entry;
  });
  const out = new Uint8Array(12 + entries.reduce((n, e) => n + e.length, 0));
  out.set(encoder.encode("DIRC"), 0);
  const view = new DataView(out.buffer);
  view.setUint32(4, version);
  view.setUint32(8, paths.length);
  let offset = 12;
  for (const entry of entries) {
    out.set(entry, offset);
    offset += entry.length;
  }
  return out;
}
