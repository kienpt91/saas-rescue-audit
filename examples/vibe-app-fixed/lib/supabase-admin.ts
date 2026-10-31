import "server-only";
import { createClient } from "@supabase/supabase-js";

/** Service-role client. Bypasses RLS: import it only from server code that has authenticated the caller another way (webhooks). */
export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false },
});
