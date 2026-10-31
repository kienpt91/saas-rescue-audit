import { createClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import { rateLimit } from "@/lib/rate-limit";
import { safeNextPath } from "@/lib/redirect";

export async function GET(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  if (!rateLimit(`auth-callback:${ip}`, 30, 60_000)) {
    return NextResponse.json({ error: "rate limited" }, { status: 429 });
  }

  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const next = safeNextPath(searchParams.get("next"));

  if (code) {
    const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
    await supabase.auth.exchangeCodeForSession(code);
  }

  return NextResponse.redirect(`${origin}${next}`);
}
