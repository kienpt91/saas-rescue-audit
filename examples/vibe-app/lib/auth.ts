import { cookies } from "next/headers";
import { supabase } from "@/lib/supabase";

export async function getUser() {
  const token = (await cookies()).get("sb-access-token")?.value;
  if (!token) return null;
  const { data } = await supabase.auth.getUser(token);
  return data.user;
}
