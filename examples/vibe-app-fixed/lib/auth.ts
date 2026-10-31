import { cookies } from "next/headers";
import { createClient, type SupabaseClient, type User } from "@supabase/supabase-js";

export type Session = { user: User; db: SupabaseClient };

/**
 * Resolves the signed-in user from the access-token cookie. The returned client
 * carries the user's own token, so row level security applies to every query made
 * with it. Returns null when there is no valid session.
 */
export async function requireUser(): Promise<Session | null> {
  const token = (await cookies()).get("sb-access-token")?.value;
  if (!token) return null;

  const db = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false },
  });
  const { data, error } = await db.auth.getUser(token);
  if (error || !data.user) return null;
  return { user: data.user, db };
}
