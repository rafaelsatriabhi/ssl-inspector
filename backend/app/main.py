"""HTTP API: GET /api/inspect?target=example.com"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app.inspector import InspectionError, inspect, parse_target
from app.models import InspectionReport

app = FastAPI(title="SSL/TLS Certificate Inspector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # the Next.js dev server
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/inspect", response_model=InspectionReport)
async def inspect_endpoint(
    target: str = Query(..., max_length=300, description="Domain, host:port or URL"),
) -> InspectionReport:
    try:
        host, port = parse_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    try:
        # inspect() uses blocking sockets, so keep it off the event loop.
        return await run_in_threadpool(inspect, host, port)
    except InspectionError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None
