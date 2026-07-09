# TrustLens

**A transparent trust score for every XRP Ledger token.**
Paste any XRPL token → get a 0-100 safety score and the reasons behind it.

Free on the web for humans · a JSON API for wallets/DEXs · an **x402 pay-per-call**
endpoint for AI agents · an **MCP tool** for Claude / Cursor / agent frameworks.

---

## Why this exists

XRPL is in an active scam epidemic — fake RLUSD/OUSD stablecoins, fake "Ripple
payout" tokens, NFT-drainer scams — and today they're flagged largely *by hand*.
Solana has RugCheck as essential infrastructure; **XRPL has no integration-ready
trust-score oracle.**

At the same time Ripple has launched the **XRPL AI Starter Kit** for agentic
payments (x402 on XRPL). The natural first thing an autonomous agent should do
before it spends money on a token is *check whether the token is a rug.*
TrustLens is that check — and it's also a flagship **x402-payable** service, so it
rides the agentic-payments narrative while having real human demand from day one.

## The four surfaces (all built, all tested)

| Surface | Endpoint / entry | For | Status |
|---|---|---|---|
| Web page | `GET /` | humans | ✅ |
| Free JSON API | `GET /api/score?issuer=&currency=` | wallets/DEXs, light use | ✅ |
| x402 metered API | `GET /api/score/pro?...` (0.01 XRP/call) | AI agents, commercial | ✅ live paid call |
| MCP tool | `mcp_server.py` → `trustlens_score` | Claude / Cursor / agents | ✅ |

Scoring reads XRPL **mainnet** (real tokens, read-only, no wallet).
The x402 payment layer settles on **testnet** during the MVP — no real funds move.

## Proof it works end to end

A live agent payment for a score (XRPL testnet):
`tx C07D3BD0406EED702863ACFCE1F230268FCAD5EB58C7A4AD1A95F1D185CBCDEA` —
Payment, 10000 drops (0.01 XRP), buyer → merchant, `tesSUCCESS`.
https://testnet.xrpl.org/transactions/C07D3BD0406EED702863ACFCE1F230268FCAD5EB58C7A4AD1A95F1D185CBCDEA

## Scoring signals (transparent, tunable)

Every point added or removed is a **named, inspectable** signal — no black box:

- **Identity** — does the issuer publish a domain? (judged first; everything else
  is weighted in its light)
- **Issuer control** — blackholed (immutable supply) vs multisig-governed vs
  anonymous-and-mintable (infinite-mint rug risk)
- **Freeze / clawback** — global freeze on? can the issuer seize your tokens?
  (expected for a verified stablecoin, a red flag on an anonymous token)
- **Impersonation** — name mimics RLUSD/XRP/USDC from an unverified issuer
- **Distribution** — holder count + top-holder concentration
- **Liquidity** — is there an AMM pool to exit into?

Verdict bands: `trusted` ≥75 · `caution` ≥55 · `risky` ≥35 · `danger` <35.

## Run it

Uses the existing `x402-sandbox` venv (already has fastapi/uvicorn/xrpl-py/x402-xrpl).

```powershell
$PY = "C:/Users/bjorn/XGROW/x402-sandbox/venv/Scripts/python.exe"

# web + API server on :8080
& $PY -m uvicorn trustlens.app:app --app-dir C:/Users/bjorn/XGROW/trustlens --port 8080

# score a token from the terminal
& $PY score_cli.py rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz SOLO

# run the scoring unit tests
& $PY tests/test_scoring.py

# the agentic loop: an agent pays 0.01 testnet XRP and gets a score (server must be up)
& $PY paid_agent.py rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De RLUSD

# MCP server (stdio) — register in Claude/Cursor mcp config, see mcp_server.py header
& $PY mcp_server.py
```

## Layout

```
trustlens/
  trustlens/
    ledger.py     read-only XRPL mainnet data access (JSON-RPC, failover)
    scoring.py    the trust-score engine (signals -> score + reasons)
    app.py        FastAPI: web page + free API + x402 paid API
  mcp_server.py   stdlib-only MCP server (agent-native surface)
  paid_agent.py   demo agent that pays via x402 for a score
  score_cli.py    terminal scorer
  tests/test_scoring.py   deterministic scoring tests (mocked ledger)
```

## Roadmap (not in the MVP)

- Full `xrp-ledger.toml` domain verification (currently: domain-set check)
- Exact top-holder concentration (currently sampled over first pages)
- A public **directory** of x402-payable XRPL services (TrustLens as the first
  listing) + agent-side discovery — the two-sided agent-economy flywheel
- Wallet/DEX integrations (embed the score at the point of trade)

## Disclaimer

TrustLens is an on-ledger risk **heuristic**, not financial advice and not a
guarantee of safety. Always do your own research.
