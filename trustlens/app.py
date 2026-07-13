"""TrustLens API + web app.

Three surfaces over one scoring engine:
  GET /                      human web page (free)
  GET /api/score            free JSON API (rate-limited, for humans / light use)
  GET /api/score/pro        x402-metered JSON API (for AI agents / commercial use)

Scoring reads XRPL *mainnet* (real tokens). The x402 payment layer settles on
*testnet* during the MVP, so no real funds move while we build and demo.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .ledger import LedgerError
from .scoring import list_currencies, score_token

# The web UI lives in its own file (was a giant inline string): no Python quote-
# escaping hazards, proper editor highlighting, and a cleaner diff history.
INDEX_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

app = FastAPI(title="TrustLens", version="0.2.0")


@app.exception_handler(LedgerError)
def ledger_error_handler(request: Request, exc: LedgerError) -> JSONResponse:
    """All public XRPL RPC endpoints transiently failed for this request.

    Better to say so honestly than to let it surface as an opaque 500, and
    definitely better than any code path that could mistake "the ledger didn't
    answer" for "this token doesn't exist" (see ledger.py's _TRANSIENT_RPC_ERRORS).
    """
    return JSONResponse(
        {"detail": "Live XRPL data is temporarily unavailable. Please try again."},
        status_code=503,
    )

# --- x402 paid tier -------------------------------------------------------------
# Reuses the proven x402-xrpl flow from x402-sandbox. Testnet merchant + facilitator.
MERCHANT_ADDRESS = os.environ.get("TRUSTLENS_PAYTO", "rHTEGqvwnBNNENEmUT7f1Ch7B3cVh1G7M4")
FACILITATOR_URL = os.environ.get("TRUSTLENS_FACILITATOR", "https://xrpl-facilitator-testnet.t54.ai")
PRICE_DROPS = os.environ.get("TRUSTLENS_PRICE_DROPS", "10000")  # 0.01 XRP per call
# Public origin this instance is reachable at (e.g. "https://trustlens.example.com").
# Unset while only running locally -- resource URLs fall back to a relative path,
# which is honest (no public origin exists yet) but not crawlable by a directory.
BASE_URL = os.environ.get("TRUSTLENS_BASE_URL", "").rstrip("/")

PRO_PATH = "/api/score/pro"
PRO_DESCRIPTION = "TrustLens token trust score (per call)"
PRO_RESOURCE_URL = f"{BASE_URL}{PRO_PATH}" if BASE_URL else PRO_PATH

try:
    from x402_xrpl.server import require_payment

    app.middleware("http")(
        require_payment(
            path=PRO_PATH,
            price=PRICE_DROPS,
            pay_to_address=MERCHANT_ADDRESS,
            network="xrpl:1",
            asset="XRP",
            facilitator_url=FACILITATOR_URL,
            # `resource` becomes the 402 body's resource.url. It must be the real,
            # fetchable URL of the paid endpoint (not an opaque label) so a directory
            # crawler (e.g. the XRPL AI Hub) can link straight to it.
            resource=PRO_RESOURCE_URL,
            description=PRO_DESCRIPTION,
            source_tag=804681468,
        )
    )
    X402_ENABLED = True
except Exception as exc:  # noqa: BLE001 - run without the paid tier if the SDK is missing
    X402_ENABLED = False
    _X402_ERROR = str(exc)


def _score(issuer: str, currency: str) -> dict:
    return score_token(issuer.strip(), currency).to_dict()


@app.get("/api/score")
def api_score(issuer: str = Query(...), currency: str | None = Query(None)) -> JSONResponse:
    """Free token score. In production this tier is rate-limited per IP.

    ``currency`` is optional: a single XRPL address can issue more than one
    token, so it isn't always a unique key on its own. If omitted, we look up
    what the issuer actually has in circulation. Exactly one -> score it
    directly. More than one -> ask the caller to pick (this is a free-tier-only
    convenience; the paid endpoint below always requires an explicit currency
    so an agent is never charged for an ambiguous lookup).
    """
    issuer = issuer.strip()
    if currency:
        return JSONResponse(_score(issuer, currency))

    options = list_currencies(issuer)
    if not options:
        return JSONResponse(
            {"detail": "This issuer has no recognized tokens in circulation."},
            status_code=404,
        )
    if len(options) == 1:
        return JSONResponse(_score(issuer, options[0]["currency"]))
    return JSONResponse({"disambiguation": True, "issuer": issuer, "currencies": options})


@app.get("/api/score/pro")
def api_score_pro(issuer: str = Query(...), currency: str = Query(...)) -> JSONResponse:
    """Metered token score. Gated by the x402 middleware above (0.01 XRP / call)."""
    return JSONResponse(_score(issuer, currency))


@app.get("/.well-known/x402")
def well_known_x402() -> JSONResponse:
    """x402 service discovery document.

    No formally published JSON Schema was found for this file as of 2026-07;
    this shape follows what the XRPL AI Hub's own listing page (xrpl-ai.org/join)
    says it looks for: a top-level service ``name`` plus a ``name``/``description``
    per paid resource. Re-check against the hub once we actually attempt a listing.
    """
    resources = []
    if X402_ENABLED:
        resources.append(
            {
                "resource": PRO_RESOURCE_URL,
                "name": "TrustLens Score",
                "description": PRO_DESCRIPTION,
                "mimeType": "application/json",
            }
        )
    return JSONResponse(
        {
            "name": "TrustLens",
            "description": "Transparent 0-100 trust score for any XRP Ledger token.",
            "resources": resources,
        }
    )


# GET + HEAD: uptime monitors (e.g. UptimeRobot) default to HEAD probes, and
# FastAPI does NOT auto-accept HEAD on GET-only routes -- a HEAD-only monitor was
# reading a healthy service as "405 / down" (found live 2026-07-13).
@app.api_route("/healthz", methods=["GET", "HEAD"])
def healthz() -> dict:
    return {"ok": True, "x402": X402_ENABLED}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML
