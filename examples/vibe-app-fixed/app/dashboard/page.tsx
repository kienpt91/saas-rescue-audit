"use client";

import { useEffect, useState } from "react";

type Project = { id: string; name: string };

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    fetch("/api/projects")
      .then((res) => (res.ok ? res.json() : []))
      .then(setProjects);
  }, []);

  return (
    <ul>
      {projects.map((p) => (
        <li key={p.id}>{p.name}</li>
      ))}
    </ul>
  );
}
