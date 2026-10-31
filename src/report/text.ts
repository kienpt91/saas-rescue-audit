/**
 * Everything a report prints that came from the audited repository (file names, policy names,
 * source lines, package name, warnings) is untrusted. This module makes such text safe for two
 * sinks: a terminal, where control and bidirectional-override characters can rewrite the screen,
 * and Markdown, where backticks, pipes, brackets, HTML and newlines can break out of the structure
 * the report is built from. The JSON report keeps the text as it is.
 */

/**
 * C0 and C1 controls (including ESC, which starts ANSI and OSC sequences), DEL, the Arabic letter mark,
 * zero-width and bidirectional formatting characters, line and paragraph separators, the byte order
 * mark, interlinear annotation characters and lone surrogates.
 */
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u180e\u200b-\u200f\u2028-\u202f\u205f-\u206f\ufeff\ufff9-\ufffb\ud800-\udfff]/gu;

const NAMED: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

/** Replaces every unsafe character with a visible escape such as `\x1b` or `\u{202e}`. */
export function escapeControls(text: string): string {
  return text.replace(UNSAFE, (ch) => {
    const named = NAMED[ch];
    if (named !== undefined) return named;
    const code = ch.codePointAt(0) ?? 0;
    return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u{${code.toString(16)}}`;
  });
}

/** Text for a terminal: controls and bidirectional overrides become visible escapes. */
export function terminalText(text: string): string {
  return escapeControls(text);
}

/** Text for Markdown prose, headings, list items and table cells: nothing in it can form markup, HTML or a link. */
export function mdText(text: string): string {
  return (
    escapeControls(text.replace(/[\\`*[\]<&|$@]/g, "\\$&"))
      // an underscore can only open emphasis when it follows a non-word character and precedes a non-space;
      // intraword and closing ones stay readable
      .replace(/(?<![A-Za-z0-9])_(?=\S)/g, "\\_")
      .replace(/:\/\//g, "\\://")
      .replace(/\bwww\./gi, (m) => `${m.slice(0, 3)}\\.`)
  );
}

/** An inline code span whose delimiters are longer than any backtick run inside it. */
export function mdCode(text: string, options: { table?: boolean } = {}): string {
  let body = escapeControls(text);
  if (options.table) body = body.replace(/\|/g, "\\|");
  let longest = 0;
  for (const run of body.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  const fence = "`".repeat(longest + 1);
  const pad = body.startsWith("`") || body.endsWith("`") || (body.startsWith(" ") && body.endsWith(" ")) ? " " : "";
  return `${fence}${pad}${body}${pad}${fence}`;
}

/** A fenced code block whose fence is longer than any backtick run in the content, so the content cannot close it. */
export function mdFence(lines: readonly string[]): string[] {
  const content = lines.map(escapeControls);
  let longest = 0;
  for (const line of content) for (const run of line.match(/`+/g) ?? []) longest = Math.max(longest, run.length);
  const fence = "`".repeat(Math.max(3, longest + 1));
  return [fence, ...content, fence];
}
