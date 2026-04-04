import type { Config, Context } from "@netlify/functions";

export default async (req: Request, context: Context) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminPassword) {
    return Response.json({ error: "Admin authentication is not configured" }, { status: 503 });
  }

  const body = await req.json();
  const { password } = body;

  if (!password || typeof password !== "string") {
    return Response.json({ error: "Password is required" }, { status: 400 });
  }

  if (password !== adminPassword) {
    return Response.json({ error: "Incorrect password" }, { status: 401 });
  }

  return Response.json({ ok: true });
};

export const config: Config = {
  path: "/api/auth",
  method: ["POST"],
};
