"use client";

import { useEffect, useState } from "react";
import { createClient } from "@supabase/supabase-js";

type Project = { id: string; name: string };

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    const admin = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
    );
    admin
      .from("projects")
      .select("id, name")
      .then(({ data }) => setProjects(data ?? []));
  }, []);

  return (
    <ul>
      {projects.map((p) => (
        <li key={p.id}>{p.name}</li>
      ))}
    </ul>
  );
}
