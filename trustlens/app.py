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

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

from .scoring import list_currencies, score_token

app = FastAPI(title="TrustLens", version="0.1.0")

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


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "x402": X402_ENABLED}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TrustLens - a trust score for XRPL tokens</title>
<style>
  :root { --bg:#0b1020; --card:#151b30; --line:#28304d; --text:#e7ecff; --muted:#93a0c8;
          --good:#28c76f; --caution:#ffb020; --risky:#ff7a45; --danger:#ff4d5e; }
  * { box-sizing:border-box; }
  body { margin:0; background:radial-gradient(1200px 600px at 50% -10%, #1a2340, var(--bg));
         color:var(--text); font:16px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,Arial; }
  .wrap { max-width:760px; margin:0 auto; padding:48px 20px 80px; }
  h1 { font-size:34px; margin:0 0 6px; letter-spacing:-.5px; }
  .sub { color:var(--muted); margin:0 0 28px; }
  form { display:flex; gap:10px; flex-wrap:wrap; }
  input { flex:1 1 220px; padding:14px 16px; border-radius:12px; border:1px solid var(--line);
          background:#0e142a; color:var(--text); font-size:15px; }
  button { padding:14px 22px; border:0; border-radius:12px; background:#4c6fff; color:#fff;
           font-weight:600; font-size:15px; cursor:pointer; }
  button:disabled { opacity:.6; cursor:progress; }
  .examples { margin:14px 0 0; color:var(--muted); font-size:14px; }
  .examples a { color:#9db2ff; cursor:pointer; text-decoration:none; margin-right:12px; }
  .card { margin-top:28px; background:var(--card); border:1px solid var(--line);
          border-radius:18px; padding:26px; display:none; }
  .head { display:flex; align-items:center; gap:22px; }
  .gauge { width:104px; height:104px; border-radius:50%; display:grid; place-items:center;
           font-size:30px; font-weight:800; flex:0 0 auto; }
  .verdict { font-size:22px; font-weight:700; text-transform:capitalize; }
  .name { color:var(--muted); font-size:14px; word-break:break-all; }
  .reasons { list-style:none; padding:0; margin:22px 0 0; }
  .reasons li { display:flex; gap:12px; padding:10px 0; border-top:1px solid var(--line); }
  .pts { font-variant-numeric:tabular-nums; font-weight:700; min-width:42px; }
  .sev { font-size:11px; text-transform:uppercase; letter-spacing:.5px; padding:2px 8px;
         border-radius:999px; align-self:center; }
  .foot { margin-top:22px; color:var(--muted); font-size:12px; }
  .err { color:var(--danger); margin-top:18px; display:none; }
  .badge { display:inline-block; font-size:12px; color:var(--muted); border:1px solid var(--line);
           padding:4px 10px; border-radius:999px; margin-bottom:22px; }
  .picker { margin-top:28px; display:none; }
  .picker .hint { color:var(--muted); font-size:14px; margin:0 0 12px; }
  .chip { display:inline-flex; align-items:center; gap:6px; padding:9px 14px; margin:0 8px 8px 0;
          border-radius:10px; border:1px solid var(--line); background:#0e142a; color:var(--text);
          font-size:14px; cursor:pointer; }
  .chip:hover { border-color:#4c6fff; }
  .linkrow { margin-top:16px; display:flex; align-items:center; gap:10px; }
  .linkbtn { background:none; border:1px solid var(--line); color:var(--muted); font-size:12px;
             padding:6px 12px; border-radius:8px; cursor:pointer; }
  .linkbtn:hover { color:var(--text); border-color:#4c6fff; }
</style>
</head>
<body>
<div class="wrap">
  <div class="badge">XRPL mainnet - read-only - no wallet needed</div>
  <h1>TrustLens</h1>
  <p class="sub">Paste any XRP Ledger token. Get a 0-100 trust score and the reasons behind it.</p>
  <form id="f">
    <input id="issuer" placeholder="Issuer address (r...)" autocomplete="off"/>
    <input id="currency" placeholder="Currency (optional)" autocomplete="off" style="flex:0 1 220px"/>
    <button id="go" type="submit">Check</button>
  </form>
  <div class="examples">
    Try:
    <a data-i="rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De" data-c="">RLUSD</a>
    <a data-i="rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz" data-c="">SOLO</a>
  </div>
  <div class="err" id="err"></div>
  <div class="picker" id="picker">
    <p class="hint" id="pickerHint"></p>
    <div id="pickerChips"></div>
  </div>
  <div class="card" id="card">
    <div class="head">
      <div class="gauge" id="gauge">--</div>
      <div>
        <div class="verdict" id="verdict"></div>
        <div class="name" id="name"></div>
      </div>
    </div>
    <ul class="reasons" id="reasons"></ul>
    <div class="foot" id="foot"></div>
    <div class="linkrow">
      <button class="linkbtn" id="copyLink" type="button">Copy link to this result</button>
      <span class="linkbtn" id="copied" style="display:none; border:none; cursor:default;">Copied!</span>
    </div>
  </div>
</div>
<script>
const COLORS = { trusted:'#28c76f', caution:'#ffb020', risky:'#ff7a45', danger:'#ff4d5e' };
const SEVBG  = { good:'#153a27', low:'#33351d', medium:'#3a2a1a', high:'#3a1d20', critical:'#45161c' };
const $ = id => document.getElementById(id);

async function check(issuer, currency) {
  $('err').style.display='none'; $('card').style.display='none'; $('picker').style.display='none';
  $('go').disabled=true; $('go').textContent='Checking...';
  // Two independent slow paths: a cold-started free-tier server, or a heavily-held
  // token (e.g. SOLO has 200k+ holders -> several paginated RPC round-trips). Don't
  // name a specific cause we can't distinguish client-side -- just say it's still going,
  // so a first-time visitor doesn't assume a hung button means it's broken.
  const stillGoing = setTimeout(() => { $('go').textContent = 'Still checking (live ledger data)...'; }, 4000);
  try {
    const q = currency
      ? `issuer=${encodeURIComponent(issuer)}&currency=${encodeURIComponent(currency)}`
      : `issuer=${encodeURIComponent(issuer)}`;
    const r = await fetch(`/api/score?${q}`);
    const d = await r.json();
    if (d.detail) throw new Error(typeof d.detail==='string'?d.detail:'Bad request');
    if (d.disambiguation) { renderPicker(issuer, d.currencies); return; }
    $('issuer').value = issuer; $('currency').value = d.currency_name;
    render(d);
  } catch(e) {
    $('err').textContent = 'Could not score that token: ' + e.message;
    $('err').style.display='block';
  } finally {
    clearTimeout(stillGoing);
    $('go').disabled=false; $('go').textContent='Check';
  }
}

function renderPicker(issuer, currencies) {
  $('pickerHint').textContent =
    `This address issues ${currencies.length} different tokens. Which one?`;
  const box = $('pickerChips'); box.innerHTML = '';
  for (const c of currencies) {
    const b = document.createElement('button');
    b.className = 'chip'; b.type = 'button'; b.textContent = c.currency_name;
    b.addEventListener('click', () => check(issuer, c.currency));
    box.appendChild(b);
  }
  $('picker').style.display = 'block';
}

function render(d) {
  const c = COLORS[d.verdict] || '#4c6fff';
  const g = $('gauge');
  g.textContent = d.score;
  g.style.background = `conic-gradient(${c} ${d.score*3.6}deg, #0e142a 0)`;
  g.style.color = c;
  $('verdict').textContent = d.verdict;
  $('verdict').style.color = c;
  $('name').textContent = `${d.currency_name}  -  ${d.issuer}`;
  const ul = $('reasons'); ul.innerHTML='';
  for (const rs of d.reasons) {
    const li = document.createElement('li');
    const sign = rs.points>=0 ? '+' : '';
    const col = rs.points>=0 ? '#28c76f' : '#ff7a45';
    li.innerHTML = `<span class="pts" style="color:${col}">${sign}${rs.points}</span>`
      + `<span class="sev" style="background:${SEVBG[rs.severity]||'#222'}">${rs.severity}</span>`
      + `<span>${rs.label}</span>`;
    ul.appendChild(li);
  }
  $('foot').textContent = d.disclaimer;
  $('card').style.display='block';

  // Make the exact result shareable/deep-linkable without a page reload.
  const url = new URL(location.href);
  url.searchParams.set('issuer', d.issuer);
  url.searchParams.set('currency', d.currency_name);
  history.replaceState(null, '', url);
  $('copyLink').onclick = async () => {
    try {
      await navigator.clipboard.writeText(url.toString());
      $('copied').textContent = 'Copied!';
    } catch (e) {
      // Clipboard API can be blocked (permissions, embedding context, older browsers) --
      // fall back to a manual-copy prompt instead of the button silently doing nothing.
      window.prompt('Copy this link:', url.toString());
      return;
    }
    $('copied').style.display = 'inline'; $('copyLink').style.display = 'none';
    setTimeout(() => { $('copied').style.display = 'none'; $('copyLink').style.display = 'inline'; }, 2000);
  };
}

$('f').addEventListener('submit', e => {
  e.preventDefault();
  const i=$('issuer').value.trim(), c=$('currency').value.trim();
  if (i) check(i, c);
});
document.querySelectorAll('.examples a').forEach(a => a.addEventListener('click', () => {
  $('issuer').value=a.dataset.i; $('currency').value=a.dataset.c; check(a.dataset.i, a.dataset.c);
}));

// Deep link: /?issuer=...&currency=... loads pre-filled and auto-runs, so a link
// shared from X (or the "Copy link to this result" button above) lands on the
// actual scored result instead of an empty form.
(() => {
  const p = new URLSearchParams(location.search);
  const i = p.get('issuer'), c = p.get('currency') || '';
  if (i) { $('issuer').value = i; $('currency').value = c; check(i, c); }
})();
</script>
</body>
</html>"""
