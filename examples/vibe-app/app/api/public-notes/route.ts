import { NextResponse } from "next/server";
import { supabase } from "@/lib/supabase";

export async function GET(request: Request) {
  const { data } = await supabase.from("notes").select("id, body, user_id").limit(100);
  const origin = request.headers.get("origin") ?? "*";

  return new NextResponse(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
    },
  });
}
