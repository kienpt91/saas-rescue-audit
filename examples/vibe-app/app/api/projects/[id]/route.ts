import { NextResponse } from "next/server";
import { getUser } from "@/lib/auth";
import { supabase } from "@/lib/supabase";

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { id } = await params;
  await supabase.from("projects").delete().eq("id", id);
  return NextResponse.json({ ok: true });
}
