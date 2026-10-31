import Link from "next/link";

export default function Home() {
  return (
    <main>
      <h1>Projects and notes</h1>
      <Link href="/dashboard">Open dashboard</Link>
    </main>
  );
}
