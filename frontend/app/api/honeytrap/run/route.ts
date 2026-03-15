const BACKEND_API_BASE =
  process.env.BACKEND_API_BASE || "http://hack-nocturne-2026-production.up.railway.app/api";

export async function POST(req: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json(
      { detail: "Request body must be valid JSON" },
      { status: 400 },
    );
  }

  try {
    const upstream = await fetch(`${BACKEND_API_BASE}/honeytrap/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });

    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("Content-Type") || "application/json",
      },
    });
  } catch {
    return Response.json(
      {
        detail:
          "Honeytrap backend is unreachable. Ensure FastAPI is running at http://hack-nocturne-2026-production.up.railway.app.",
      },
      { status: 502 },
    );
  }
}
