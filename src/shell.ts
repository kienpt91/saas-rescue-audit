/** Quotes a value for a POSIX shell so that a file or package name can never be read as part of the command. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}
