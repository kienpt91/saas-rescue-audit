/**
 * A small PostgreSQL tokenizer. It does not validate SQL; it only needs to find
 * statement boundaries and keywords reliably, which means strings, quoted
 * identifiers, dollar-quoted bodies and comments must never leak their content
 * into the token stream.
 */

export type TokenKind = "word" | "qident" | "string" | "dollar" | "number" | "punct" | "op";

export interface Token {
  kind: TokenKind;
  /** Source text of the token. */
  text: string;
  /** Lower-case text for words, unquoted text for quoted identifiers, content for strings. */
  value: string;
  /** 1-based line of the first character. */
  line: number;
}

const OP_CHARS = "+-*/<>=~!@#%^&|`?:";
const PUNCT_CHARS = "(),;.[]";
const WORD_START = /[A-Za-z_\u0080-\uffff]/;
const WORD_PART = /[A-Za-z0-9_$\u0080-\uffff]/;
const DIGIT = /[0-9]/;

export function tokenize(sql: string): Token[] {
  const tokens: Token[] = [];
  const n = sql.length;
  let i = 0;
  let line = 1;

  const advanceTo = (end: number): void => {
    for (let k = i; k < end; k++) if (sql[k] === "\n") line++;
    i = end;
  };

  while (i < n) {
    const ch = sql[i]!;
    const next = sql[i + 1];

    if (ch === "\n" || ch === " " || ch === "\t" || ch === "\r" || ch === "\f") {
      if (ch === "\n") line++;
      i++;
      continue;
    }

    // line comment
    if (ch === "-" && next === "-") {
      let end = sql.indexOf("\n", i);
      if (end === -1) end = n;
      i = end;
      continue;
    }

    // block comment (PostgreSQL allows nesting)
    if (ch === "/" && next === "*") {
      let depth = 1;
      let k = i + 2;
      while (k < n && depth > 0) {
        if (sql[k] === "/" && sql[k + 1] === "*") {
          depth++;
          k += 2;
        } else if (sql[k] === "*" && sql[k + 1] === "/") {
          depth--;
          k += 2;
        } else k++;
      }
      advanceTo(k);
      continue;
    }

    const startLine = line;

    // single-quoted string, optionally with E/B/X/U& prefix handled by the word path below
    if (ch === "'") {
      const end = scanQuoted(sql, i, "'", false);
      tokens.push({ kind: "string", text: sql.slice(i, end), value: unescapeQuoted(sql.slice(i + 1, Math.max(i + 1, end - 1)), "'"), line: startLine });
      advanceTo(end);
      continue;
    }

    // quoted identifier
    if (ch === '"') {
      const end = scanQuoted(sql, i, '"', false);
      tokens.push({ kind: "qident", text: sql.slice(i, end), value: unescapeQuoted(sql.slice(i + 1, Math.max(i + 1, end - 1)), '"'), line: startLine });
      advanceTo(end);
      continue;
    }

    // dollar-quoted string: $$ ... $$ or $tag$ ... $tag$
    if (ch === "$") {
      const m = /^\$([A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)?\$/.exec(sql.slice(i, i + 80));
      if (m) {
        const tag = m[0];
        const close = sql.indexOf(tag, i + tag.length);
        const end = close === -1 ? n : close + tag.length;
        const body = sql.slice(i + tag.length, close === -1 ? n : close);
        tokens.push({ kind: "dollar", text: sql.slice(i, end), value: body, line: startLine });
        advanceTo(end);
        continue;
      }
    }

    // E'...' escape strings (backslash escapes)
    if ((ch === "E" || ch === "e") && next === "'") {
      const end = scanQuoted(sql, i + 1, "'", true);
      tokens.push({ kind: "string", text: sql.slice(i, end), value: sql.slice(i + 2, Math.max(i + 2, end - 1)), line: startLine });
      advanceTo(end);
      continue;
    }

    if (WORD_START.test(ch)) {
      let k = i + 1;
      while (k < n && WORD_PART.test(sql[k]!)) k++;
      const text = sql.slice(i, k);
      tokens.push({ kind: "word", text, value: text.toLowerCase(), line: startLine });
      i = k;
      continue;
    }

    if (DIGIT.test(ch) || (ch === "$" && next !== undefined && DIGIT.test(next))) {
      let k = i + 1;
      while (k < n && /[0-9A-Za-z_.$]/.test(sql[k]!)) {
        // stop before "..", which is not valid in a number
        if (sql[k] === "." && sql[k + 1] === ".") break;
        k++;
      }
      const text = sql.slice(i, k);
      tokens.push({ kind: "number", text, value: text.toLowerCase(), line: startLine });
      i = k;
      continue;
    }

    if (PUNCT_CHARS.includes(ch)) {
      tokens.push({ kind: "punct", text: ch, value: ch, line: startLine });
      i++;
      continue;
    }

    if (OP_CHARS.includes(ch)) {
      let k = i + 1;
      while (k < n && OP_CHARS.includes(sql[k]!) && !(sql[k] === "-" && sql[k + 1] === "-") && !(sql[k] === "/" && sql[k + 1] === "*")) k++;
      const text = sql.slice(i, k);
      tokens.push({ kind: "op", text, value: text, line: startLine });
      i = k;
      continue;
    }

    // unknown character: skip it
    i++;
  }

  return tokens;
}

/** Returns the index just after the closing quote (or end of input when unterminated). */
function scanQuoted(sql: string, start: number, quote: string, backslash: boolean): number {
  let k = start + 1;
  while (k < sql.length) {
    const c = sql[k]!;
    if (backslash && c === "\\") {
      k += 2;
      continue;
    }
    if (c === quote) {
      if (sql[k + 1] === quote) {
        k += 2;
        continue;
      }
      return k + 1;
    }
    k++;
  }
  return sql.length;
}

function unescapeQuoted(inner: string, quote: string): string {
  return inner.split(quote + quote).join(quote);
}

/** Joins tokens back into a compact, single-spaced string for evidence output. */
export function tokensToText(tokens: readonly Token[]): string {
  let out = "";
  for (const t of tokens) {
    const needsSpace = out !== "" && !(t.kind === "punct" && (t.text === ")" || t.text === "," || t.text === "." || t.text === "(" || t.text === "[" || t.text === "]")) && !/[(.[]$/.test(out);
    out += (needsSpace ? " " : "") + t.text;
  }
  return out;
}
