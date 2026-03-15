const BACKEND_API_BASE =
  process.env.BACKEND_API_BASE || "http://hack-nocturne-2026-production.up.railway.app/api";

export async function GET(req: Request): Promise<Response> {
  const { search } = new URL(req.url);
  try {
    const upstream = await fetch(
      `${BACKEND_API_BASE}/honeytrap/intel${search}`,
      {
        method: "GET",
        cache: "no-store",
      },
    );

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
