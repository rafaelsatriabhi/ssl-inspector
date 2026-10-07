# Project #1: SSL/TLS Certificate Inspector

Enter a domain and get its certificate chain, expiry, issuer, SANs, key type/size,
TLS version, cipher suite and an A+..F grade, like a mini SSL Labs.

Part of the roadmap in `~/Documents/cybersecurity-projects-roadmap.md`.

## Status

- [x] Backend (FastAPI): inspection, grading, API, tests
- [x] Frontend (Next.js): grade, findings and chain tree view

## Run the backend

```bash
cd backend
.venv/bin/uvicorn app.main:app --reload       # http://localhost:8000/docs
.venv/bin/python -m pytest -q                 # offline tests
```

Try: `curl "localhost:8000/api/inspect?target=github.com"`

## Run the frontend

```bash
cd frontend
npm install        # first time only
npm run dev        # http://localhost:3000 (the backend must be running on :8000)
```

Open `http://localhost:3000/?target=github.com` to run an inspection straight from the URL.
To point at a different backend, set `NEXT_PUBLIC_API_URL` (and add that origin to the CORS list in `app/main.py`).

Fresh backend setup (if `.venv` is missing): `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
(on Ubuntu this needs `sudo apt install python3.12-venv` first).

To inspect hosts on your own network, start the server with `ALLOW_PRIVATE_TARGETS=1`.
By default it refuses private/loopback addresses so it can't be abused for SSRF.

## How it works

| File | What it does |
| --- | --- |
| `app/inspector.py` | Two TLS handshakes. Pass 1 accepts anything and records the protocol, cipher and the raw chain. Pass 2 verifies the chain and hostname against the system CA store. |
| `app/grading.py` | Starts at 100 points; problems subtract points or cap the grade (expired/untrusted → F, TLS 1.0/1.1 → C, no forward secrecy → B, any warning → A). |
| `app/models.py` | The JSON response shape. |
| `app/main.py` | `GET /api/inspect?target=...` |
| `frontend/app/page.js` | Search box, example targets, fetches `/api/inspect` |
| `frontend/app/components/` | `ReportSummary` (grade + connection), `Findings`, `ChainTree` (Leaf → Intermediate → Root) |
| `frontend/lib/certWarnings.js` | Per-certificate red/amber flags, following the rules in `grading.py` |
| `tests/` | Builds a throwaway root → intermediate → leaf PKI and a local TLS server, so the tests don't need the internet. |

Good sites to test against: https://badssl.com (`expired.`, `self-signed.`, `wrong.host.`,
`untrusted-root.`, `tls-v1-0.badssl.com:1010`, `static-rsa.`).

## Things to learn from the code

- Why the inspector does two handshakes (you can't see a broken chain if you refuse to connect to it)
- `SECLEVEL=0` and `MINIMUM_SUPPORTED`: modern OpenSSL refuses weak setups by default, and a scanner has to opt back in
- Python 3.12 has no public API for the peer's chain; `_sslobj.get_unverified_chain()` (public in 3.13)
- Leaf/intermediate/root roles: a "root" is self-signed. Chains like github.com's end in a cross-signed intermediate instead.
