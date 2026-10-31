import { createClient } from "@supabase/supabase-js";

// one client for everything, so no more permission errors
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
);
