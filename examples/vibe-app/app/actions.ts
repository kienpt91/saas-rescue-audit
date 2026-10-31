"use server";

import { supabase } from "@/lib/supabase";

export async function deleteNote(noteId: string) {
  await supabase.from("notes").delete().eq("id", noteId);
}
