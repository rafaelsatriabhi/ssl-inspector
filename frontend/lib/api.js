// The FastAPI backend. Its CORS settings allow http://localhost:3000 (the Next.js dev server).
export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Call GET /api/inspect and return the InspectionReport (see backend/app/models.py). */
export async function inspectTarget(target, signal) {
  let res;
  try {
    res = await fetch(`${API_URL}/api/inspect?target=${encodeURIComponent(target)}`, { signal });
  } catch (e) {
    if (e.name === "AbortError") throw e;
    throw new Error(`Could not reach the backend at ${API_URL}. Is uvicorn running?`);
  }

  const body = await res.json().catch(() => null);
  if (!res.ok) {
    // FastAPI puts errors in "detail": a string for our HTTPExceptions (400/502),
    // or a list of objects for request validation errors (422).
    const detail = body?.detail;
    const message = typeof detail === "string" ? detail : detail?.[0]?.msg;
    throw new Error(message ?? `Request failed with status ${res.status}`);
  }
  return body;
}
