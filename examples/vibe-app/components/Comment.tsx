export function Comment({ html }: { html: string }) {
  return <div className="comment" dangerouslySetInnerHTML={{ __html: html }} />;
}
