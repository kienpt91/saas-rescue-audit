"use server";

import { requireUser } from "@/lib/auth";

export async function deleteNote(noteId: string) {
  const session = await requireUser();
  if (!session) throw new Error("unauthorized");

  await session.db.from("notes").delete().eq("id", noteId).eq("user_id", session.user.id);
}
