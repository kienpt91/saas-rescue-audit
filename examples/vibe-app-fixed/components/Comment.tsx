/** Renders user-supplied text. JSX escapes it, so no HTML from the comment reaches the DOM. */
export function Comment({ text }: { text: string }) {
  return <div className="comment">{text}</div>;
}
