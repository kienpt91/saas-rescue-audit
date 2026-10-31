import { NextResponse } from "next/server";
import { requireUser } from "@/lib/auth";

export async function GET() {
  const session = await requireUser();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { data, error } = await session.db
    .from("projects")
    .select("id, name, created_at")
    .eq("user_id", session.user.id);
  if (error) return NextResponse.json({ error: "query failed" }, { status: 500 });
  return NextResponse.json(data);
}

export async function POST(request: Request) {
  const session = await requireUser();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const body: unknown = await request.json();
  const name = typeof body === "object" && body !== null && "name" in body && typeof body.name === "string" ? body.name.trim() : "";
  if (name.length === 0 || name.length > 120) {
    return NextResponse.json({ error: "name must be 1-120 characters" }, { status: 400 });
  }

  const { data, error } = await session.db
    .from("projects")
    .insert({ name, user_id: session.user.id })
    .select("id, name")
    .single();
  if (error) return NextResponse.json({ error: "insert failed" }, { status: 500 });
  return NextResponse.json(data, { status: 201 });
}
