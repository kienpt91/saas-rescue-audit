import { NextResponse } from "next/server";
import { requireUser } from "@/lib/auth";

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await requireUser();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { id } = await params;
  const { data } = await session.db
    .from("projects")
    .delete()
    .eq("id", id)
    .eq("user_id", session.user.id)
    .select("id");
  if (!data || data.length === 0) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ ok: true });
}
